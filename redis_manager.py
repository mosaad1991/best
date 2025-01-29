from redis.asyncio.retry import Retry
from typing import Dict, List, Optional, Any, Callable
import redis.asyncio as redis
import logging
import json
import os
import asyncio
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timezone


class RedisServiceName(str, Enum):
    MERNA = "merna"
    AQRABENO = "aqrabeno"
    SWALF = "swalf"
    MOSAAD = "mosaad"


@dataclass
class RedisCredentials:
    """بيانات اعتماد Redis"""
    username: str
    password: str
    api_key: str
    account_name: str = ""
    account_number: str = ""


# تكوين بيانات الاعتماد لكل خدمة Redis
REDIS_CREDENTIALS: Dict[RedisServiceName, RedisCredentials] = {
    RedisServiceName.MERNA: RedisCredentials(
        username="default",
        password="C5wRViuYDN572jYpOTaq0pKbTqWlOEy8",
        api_key="A2aj6oe0qnvvw5dc78qwi7lqdhidzqt4i0xdvilwid1v8n0vnod",
        account_name="Merna",
        account_number="2300743"
    ),
    RedisServiceName.AQRABENO: RedisCredentials(
        username="default",
        password="p7IVGuYNa4Kua0grhTVvb3RMTZIFGFv4",
        api_key="A3jt455kvjgvdd9daclr5vy4wptrxieb4k5ipgv26co8a9lay3v"
    ),
    RedisServiceName.SWALF: RedisCredentials(
        username="default",
        password="jZXo17RMWc6yWvJOSbgAC0Yv8uJBKJLG",
        api_key="A2lrml8qrte1am5jek0r59ak1tm3tz5z2ub0sqkfzgaz7zubjwf"
    ),
    RedisServiceName.MOSAAD: RedisCredentials(
        username="default",
        password="OGdBw95euCAhVbjynjxGSMwTE9cmma5D",
        api_key="A4hgtv69fgrxzae278xzmjgtkmo4ooppsbzkx4k6v96we8r2xvq",
    )
}


class RedisConnectionError(Exception):
    """خطأ اتصال Redis مخصص"""
    pass


class EnhancedRedisManager:
    """مدير Redis المحسن مع دعم لتعدد الاتصالات والتعافي التلقائي"""

    def __init__(self, max_retries=3, timeout=30, max_connections=20):
        """تهيئة مدير Redis"""
        self.instances: Dict[RedisServiceName, Dict[str, redis.Redis]] = {}
        self.max_retries = max_retries
        self.timeout = timeout
        self.max_connections = max_connections
        self.current_service = None
        self._initialize_urls()
        self._health_check_interval = 60  # ثانية
        self._health_check_task = None

    def _initialize_urls(self):
        """تهيئة عناوين Redis"""
        self._redis_urls = {}
        for service in RedisServiceName:
            url = os.getenv(f'REDIS_{service.upper()}_URL')
            if url:
                self._redis_urls[service] = url
                credentials = REDIS_CREDENTIALS.get(service)
                if credentials:
                    # تحديث عنوان URL بمعلومات المصادقة
                    self._redis_urls[service] = self._update_url_with_credentials(url, credentials)

    def _update_url_with_credentials(self, url: str, credentials: RedisCredentials) -> str:
        """تحديث عنوان URL مع بيانات الاعتماد"""
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url)
            netloc = f"{credentials.username}:{credentials.password}@{parsed.hostname}"
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        except Exception as e:
            logging.error(f"خطأ في تحديث URL: {str(e)}")
            return url

    async def init_connections(self) -> None:
        """تهيئة جميع اتصالات Redis"""
        logging.debug("🔍 Initializing Redis connections...")

        try:
            if not self._redis_urls:
                logging.debug("❌ No Redis URLs found in environment variables.")
                raise ValueError("No Redis URLs configured")

            connection_errors = []
            successful_connections = 0

            for service_name in RedisServiceName:
                url = self._redis_urls.get(service_name)
                if not url:
                    logging.debug(f"⚠️ No URL configured for service: {service_name}")
                    continue

                for attempt in range(self.max_retries):
                    logging.debug(f"🔄 Attempting connection to {service_name} (Try {attempt + 1})")
                    try:
                        instances = await self._create_redis_client(service_name, url)
                        if instances:
                            await instances['text'].ping()
                            self.instances[service_name] = instances
                            successful_connections += 1

                            # تعيين الخدمة الحالية للاتصال الأول الناجح
                            if not self.current_service:
                                self.current_service = service_name

                            logging.debug(f"✅ Successfully connected to {service_name}")
                            break
                    except Exception as e:
                        logging.debug(f"❌ Connection to {service_name} failed on attempt {attempt + 1}: {e}")
                        if attempt == self.max_retries - 1:
                            connection_errors.append(f"{service_name}: {str(e)}")

            if successful_connections == 0:
                raise RedisConnectionError(f"Failed to initialize any Redis connection: {', '.join(connection_errors)}")

            logging.debug(f"✅ {successful_connections} Redis connections initialized successfully.")
            logging.debug(f"✅ Current service set to: {self.current_service}")
        except Exception as e:
            logging.critical(f"❌ Redis Manager initialization failed: {e}")
            raise

    async def _validate_current_service(self) -> None:
        """التحقق من صحة الخدمة الحالية"""
        try:
            if not self.current_service:
                raise ValueError("No current service selected")

            current_clients = self.instances[self.current_service]
            await current_clients['text'].ping()

        except Exception as e:
            logging.error(f"فشل التحقق من الخدمة الحالية: {str(e)}")
            # محاولة التبديل إلى خدمة أخرى
            await self._fallback_to_alternative_service()

    async def _fallback_to_alternative_service(self) -> None:
        """التبديل إلى خدمة بديلة في حالة فشل الخدمة الحالية"""
        for service_name in self.instances:
            if service_name != self.current_service:
                try:
                    await self.instances[service_name]['text'].ping()
                    self.current_service = service_name
                    logging.info(f"تم التبديل إلى الخدمة البديلة: {service_name}")
                    return
                except:
                    continue

        raise RedisConnectionError("فشل في العثور على خدمة بديلة متاحة")

    async def _cleanup_failed_initialization(self) -> None:
        """تنظيف الموارد في حالة فشل التهيئة"""
        try:
            # إغلاق جميع الاتصالات القائمة
            for service_instances in self.instances.values():
                for client in service_instances.values():
                    try:
                        await client.close()
                    except:
                        pass

            # إعادة تعيين المتغيرات
            self.instances = {}
            self.current_service = None

            # إيقاف مهمة فحص الصحة إذا كانت قائمة
            if self._health_check_task:
                self._health_check_task.cancel()

            logging.info("تم تنظيف الموارد بنجاح بعد فشل التهيئة")

        except Exception as e:
            logging.error(f"خطأ أثناء تنظيف الموارد: {str(e)}")

    async def _update_connection_status(self, is_connected: bool) -> None:
        """تحديث حالة الاتصال في Redis"""
        try:
            status = {
                'connected': is_connected,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'service_count': len(self.instances),
                'current_service': self.current_service
            }

            if self.current_service and self.instances:
                await self.instances[self.current_service]['text'].hset(
                    'redis_connection_status',
                    mapping=status
                )
        except:
            pass  # تجاهل أخطاء تحديث الحالة

    async def _create_redis_client(self, service_name: RedisServiceName, url: str):
        """إنشاء عميل Redis"""
        try:
            # إنشاء عميل للنصوص
            text_client = redis.Redis.from_url(
                url,
                decode_responses=True,
                retry_on_timeout=True,
                socket_connect_timeout=self.timeout,
                socket_keepalive=True,
                health_check_interval=30
            )

            # إنشاء عميل للبيانات الثنائية
            binary_client = redis.Redis.from_url(
                url,
                decode_responses=False,
                retry_on_timeout=True,
                socket_connect_timeout=self.timeout,
                socket_keepalive=True,
                health_check_interval=30
            )

            # اختبار الاتصال
            await text_client.ping()

            return {
                'text': text_client,
                'binary': binary_client
            }

        except Exception as e:
            logging.error(f"خطأ في إنشاء عميل Redis: {str(e)}")
            return None

    async def _start_health_check(self):
        """بدء مهمة فحص الصحة الدورية"""
        if self._health_check_task:
            self._health_check_task.cancel()

        self._health_check_task = asyncio.create_task(self._health_check_loop())

    async def _health_check_loop(self):
        """حلقة فحص صحة الاتصالات"""
        while True:
            try:
                await asyncio.sleep(self._health_check_interval)
                await self._check_connections_health()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"خطأ في فحص الصحة: {str(e)}")

    async def _check_connections_health(self):
        """فحص صحة جميع الاتصالات"""
        for service_name, instances in list(self.instances.items()):
            try:
                await instances['text'].ping()
            except Exception as e:
                logging.warning(f"❌ فشل فحص صحة {service_name}: {str(e)}")
                await self._handle_connection_failure(service_name)

    async def _handle_connection_failure(self, service_name: RedisServiceName):
        """معالجة فشل الاتصال"""
        try:
            # محاولة إعادة الاتصال
            url = self._redis_urls.get(service_name)
            if url:
                new_instances = await self._create_redis_client(service_name, url)
                if new_instances:
                    self.instances[service_name] = new_instances
                    logging.info(f"✅ تم إعادة الاتصال بـ {service_name} بنجاح")
                    return

            # إزالة الخدمة الفاشلة
            self.instances.pop(service_name, None)

            # تحديث الخدمة الحالية إذا لزم الأمر
            if service_name == self.current_service and self.instances:
                self.current_service = next(iter(self.instances))

        except Exception as e:
            logging.error(f"❌ فشل في معالجة فشل الاتصال لـ {service_name}: {str(e)}")

    async def get_current_clients(self):
        """الحصول على العملاء الحاليين"""
        if not self.current_service or not self.instances:
            raise RedisConnectionError("لا توجد اتصالات Redis متاحة")
        return self.instances[self.current_service]

    async def switch_service(self, service_name: RedisServiceName):
        """تبديل الخدمة الحالية"""
        if service_name not in self.instances:
            raise ValueError(f"خدمة Redis {service_name} غير مهيأة")
        self.current_service = service_name
        return self.instances[service_name]

    async def cleanup(self):
        """تنظيف الموارد"""
        try:
            # إيقاف مهمة فحص الصحة إذا كانت موجودة
            if hasattr(self, '_health_check_task') and self._health_check_task:
                self._health_check_task.cancel()
                try:
                    await self._health_check_task
                except asyncio.CancelledError:
                    pass

            # إغلاق جميع اتصالات Redis
            if hasattr(self, 'instances'):
                for service_name, instances in self.instances.items():
                    for client_type, client in instances.items():
                        try:
                            await client.close()
                            logging.info(f"Closed {service_name} {client_type} connection")
                        except Exception as e:
                            logging.error(f"Error closing {service_name} {client_type} connection: {str(e)}")

                self.instances.clear()

            logging.info("Redis manager cleanup completed successfully")

        except Exception as e:
            logging.error(f"Error during Redis manager cleanup: {str(e)}")

    async def handle_service_failure(self) -> bool:
        """معالجة فشل الخدمة الحالية"""
        if not self.instances:
            return False

        # إزالة الخدمة الحالية
        self.instances.pop(self.current_service, None)

        # محاولة التبديل إلى خدمة أخرى
        if self.instances:
            self.current_service = next(iter(self.instances))
            return True

        return False


async def main():
    """مثال على الاستخدام"""
    logging.basicConfig(level=logging.INFO)

    # إنشاء مدير Redis
    redis_manager = EnhancedRedisManager()

    try:
        # تهيئة الاتصالات
        await redis_manager.init_connections()

        # استخدام الخدمة الافتراضية
        clients = await redis_manager.get_current_clients()
        text_client = clients['text']
        binary_client = clients['binary']

        # تجربة تخزين واسترجاع البيانات
        await text_client.set("test_key", "test_value")
        value = await text_client.get("test_key")
        logging.info(f"القيمة المخزنة: {value}")

        # التبديل إلى خدمة أخرى
        if RedisServiceName.AQRABENO in redis_manager.instances:
            await redis_manager.switch_service(RedisServiceName.AQRABENO)
            logging.info("تم التبديل إلى خدمة Aqrabeno")

    except Exception as e:
        logging.error(f"❌ خطأ: {str(e)}")
    finally:
        # تنظيف الموارد
        await redis_manager.cleanup()


if __name__ == "__main__":
    asyncio.run(main())