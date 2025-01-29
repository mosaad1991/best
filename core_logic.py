# Imports
import logging
import redis.asyncio as redis
import json
import os
import re
import requests
import google.generativeai as genai
from typing import Dict, Optional, List, Any, Union, Tuple
from datetime import datetime, timezone
import base64
from urllib.parse import quote
import random
from pydub import AudioSegment
from io import BytesIO
import asyncio
import async_timeout
from dataclasses import dataclass, field
from enum import Enum
import psutil
from prometheus_client import Counter, Gauge
import traceback
import aiohttp
from aiohttp import ClientTimeout, ClientSession
from cryptography.fernet import Fernet
from redis_manager import EnhancedRedisManager, RedisServiceName
import uuid
import aiofiles
import shutil
from logging.handlers import RotatingFileHandler
from config import (
    task_1_prompt, task_2_prompt, task_3_prompt, task_4_prompt,
    task_5_prompt, task_6_prompt, task_7_prompt,
    task_9_prompt, task_10_prompt
)
import time


# Constants
DEFAULT_AUDIO_DURATION = 60
DEFAULT_VIDEO_DIMENSIONS = 'width=1080&height=1920'
DEFAULT_SCENE_COUNT = 4
MAX_RETRIES = 3
MAX_AUDIO_SIZE = 10 * 1024 * 1024  # 10MB
MAX_RETRIES_PER_SCENE = 3  # أضفنا هذا
MAX_CONCURRENT_SCENES = 5  # أضفنا هذا


class TaskStatus(Enum):
    """تعريف حالات المهام المختلفة"""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    FAILED_CONTINUING = "failed_continuing"
    CANCELLED = "cancelled"


class TaskResult:
    """تحسين فئة TaskResult للتعامل مع التنسيقات المختلفة"""

    def __init__(self):

        self.content: Optional[Any] = None
        self.error: Optional[str] = None
        self.timestamp: Optional[str] = None
        self.duration: Optional[float] = None

    def set_success(self, content: Any) -> None:
        self.content = content
        self.error = None
        self.timestamp = datetime.now().isoformat()

    def set_error(self, error: str) -> None:
        self.error = error
        self.content = None
        self.timestamp = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return {
            'content': self.content,
            'error': self.error,
            'timestamp': self.timestamp,
            'duration': self.duration
        }

    @staticmethod
    def from_dict(data: Dict) -> 'TaskResult':
        result = TaskResult()
        result.content = data.get('content')
        result.error = data.get('error')
        result.timestamp = data.get('timestamp')
        result.duration = data.get('duration')
        return result


class CustomError(Exception):
    """قاعدة للأخطاء المخصصة"""
    pass


class APIConfigurationError(CustomError):
    """خطأ في تكوين API"""
    pass


class ContentGenerationError(CustomError):
    """خطأ في توليد المحتوى"""
    pass


class ResourceExhaustionError(CustomError):
    """خطأ في نفاد الموارد"""
    pass


class AsyncStreamingCoreLogic:
    """منطق المعالجة الأساسي للتدفق غير المتزامن"""

    def __init__(
            self,
            redis_manager: Optional[EnhancedRedisManager] = None,
            max_retries: int = 3,
            timeout: int = 30,
            chunk_size: int = 1024 * 1024,
            max_concurrent_tasks: int = 5
    ):
        if not redis_manager:
            raise ValueError("Redis manager is required")

        self.redis_manager = redis_manager

        # التأكد من وجود خدمة حالية
        if not self.redis_manager.current_service:
            raise ValueError("No active Redis service available")

        # باقي التهيئة كما هي...

            # تخزين redis_manager




        # تهيئة المتغيرات الأساسية
        self.redis = None
        self.stream_key = "task_results_stream"
        self.google_model = None
        self.eleven_labs_config = None



        # التحقق من صحة معلمات التكوين
        self.config = {
            'max_retries': max_retries,
            'timeout': timeout,
            'chunk_size': chunk_size,
            'max_concurrent_tasks': max_concurrent_tasks
        }
        # التحقق من صحة المعلمات
        self._validate_init_params(
            max_retries=max_retries,
            timeout=timeout,
            chunk_size=chunk_size,
            max_concurrent_tasks=max_concurrent_tasks
        )



        # تكوين المعلمات
        self.config = {
            'max_retries': max_retries,
            'timeout': timeout,
            'chunk_size': chunk_size,
            'max_concurrent_tasks': max_concurrent_tasks
        }

        # تهيئة إدارة المهام
        self._results = {f'task{i}': TaskResult() for i in range(1, 12)}
        self._task_statuses = {f'task{i}': TaskStatus.PENDING for i in range(1, 12)}
        self._task_locks = {f'task{i}': asyncio.Lock() for i in range(1, 12)}

        # إضافة التحكم في التزامن
        self._task_semaphores = {
            'audio': asyncio.Semaphore(2),
            'image': asyncio.Semaphore(5)
        }
        self._connection_lock = asyncio.Lock()

        # تهيئة إدارة Redis
        self.redis_manager = None

        # تهيئة المقاييس والمراقبة
        self._setup_metrics()
        self._performance_metrics = {
            'start_time': datetime.now(timezone.utc),
            'task_timings': {},
            'error_counts': {},
            'memory_usage': {}
        }

        # قائمة المهام للتنظيف
        self._cleanup_tasks = []
        self._health_check_task = None

        # إعداد التسجيل
        self._setup_logging()
        self._initialize_error_handling()

        # تعريف تبعيات المهام
        self._task_prerequisites = {
            2: [1],
            3: [2],
            4: [3],
            5: [1, 2, 4],
            6: [2, 4, 5],
            7: [2, 4, 5],
            8: [4],
            9: [4, 8],
            10: [9],
            11: [8, 10]
        }

        # إنشاء المجلدات المؤقتة
        os.makedirs('./temp', exist_ok=True)
        os.makedirs('./temp/audio', exist_ok=True)
        os.makedirs('./temp/images', exist_ok=True)

    async def init_redis(self) -> bool:
        """تهيئة اتصال Redis"""
        logging.debug("🔍 Starting Redis initialization in core logic...")

        try:
            if not self.redis_manager:
                logging.debug("❌ Redis Manager is not initialized.")
                raise ValueError("Redis manager is not initialized.")

            # الحصول على العملاء الحاليين
            clients = await self.redis_manager.get_current_clients()
            if not clients or 'text' not in clients:
                logging.debug("❌ Failed to retrieve Redis clients.")
                raise ValueError("Failed to get Redis clients")

            # تخزين عميل Redis
            self.redis = clients['text']
            logging.debug("✅ Redis client retrieved successfully.")

            # تعيين الخدمة الحالية بعد نجاح الاتصال
            if hasattr(self.redis_manager, 'current_service'):
                logging.debug(f"✅ Current Redis service set to: {self.redis_manager.current_service}")

            # اختبار الاتصال
            await self.redis.ping()
            logging.debug("✅ Redis ping successful.")

            return True
        except Exception as e:
            logging.error(f"❌ Redis initialization error: {e}", exc_info=True)
            self.redis = None
            return False

    def _setup_metrics(self) -> None:
        """تهيئة المقاييس"""
        self.metrics = {
            'task_duration': Counter(
                'task_duration_seconds',
                'Task execution duration in seconds',
                ['task_number']
            ),
            'task_errors': Counter(
                'task_errors_total',
                'Number of task errors',
                ['task_number', 'error_type']
            ),
            'resource_usage': Gauge(
                'resource_usage',
                'System resource usage',
                ['resource_type']
            ),
            'active_tasks': Gauge(
                'active_tasks',
                'Number of currently active tasks'
            ),
            'memory_usage': Gauge(
                'memory_usage_bytes',
                'Memory usage in bytes',
                ['type']
            )
        }

    def _setup_logging(self) -> None:
        """إعداد التسجيل"""
        log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('app.log', encoding='utf-8'),
                RotatingFileHandler(
                    'app_detailed.log',
                    maxBytes=10_000_000,
                    backupCount=5,
                    encoding='utf-8'
                )
            ]
        )

    def _initialize_error_handling(self) -> None:
        """تهيئة معالجة الأخطاء"""
        self._error_handlers = {
            'connection': self._handle_connection_error,
            'timeout': self._handle_timeout_error,
            'validation': self._handle_validation_error,
            'resource': self._handle_resource_error
        }
        self._error_matrix = {
            'critical': [],
            'warning': [],
            'info': []
        }

    @staticmethod
    def _validate_init_params(
            max_retries: int,
            timeout: int,
            chunk_size: int,
            max_concurrent_tasks: int
    ) -> None:
        """التحقق من صحة معلمات التهيئة"""
        # إزالة التحقق من redis_url
        if not isinstance(max_retries, int) or max_retries < 1:
            raise ValueError("max_retries must be a positive integer")
        if not isinstance(timeout, int) or timeout < 1:
            raise ValueError("timeout must be a positive integer")
        if not isinstance(chunk_size, int) or chunk_size < 1:
            raise ValueError("chunk_size must be a positive integer")
        if not isinstance(max_concurrent_tasks, int) or max_concurrent_tasks < 1:
            raise ValueError("max_concurrent_tasks must be a positive integer")



    async def stream_result(self, task_number: int, result: Dict) -> None:
        """بث نتيجة المهمة إلى Redis stream"""
        try:
            # إزالة البيانات الكبيرة
            if task_number == 8 and 'content' in result and 'audio_data' in result['content']:
                result['content'].pop('audio_data', None)

            result_data = {
                'task_number': str(task_number),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'content': json.dumps(result),
                'status': result.get('status', 'error')
            }

            # إضافة النتيجة إلى التيار
            await self.redis.xadd(
                self.stream_key,
                result_data,
                maxlen=1000  # الاحتفاظ فقط بآخر 1000 نتيجة
            )

            logging.info(f"Task {task_number} result streamed successfully")

        except Exception as e:
            logging.error(f"Error streaming task {task_number} result: {str(e)}")

    async def _health_check_loop(self) -> None:
        """حلقة فحص صحة الاتصال"""
        while True:
            try:
                await asyncio.sleep(30)  # فحص كل 30 ثانية
                if not await self._check_redis_connection():
                    await self._attempt_reconnection()
                await self._monitor_resource_usage()
                await self.cleanup_old_data()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Health check error: {str(e)}")
                await asyncio.sleep(5)

    async def _check_redis_connection(self) -> bool:
        """التحقق من حالة اتصال Redis"""
        try:
            if not self.redis:
                return False
            await self.redis.ping()
            return True
        except Exception as e:
            logging.error(f"Redis connection check failed: {str(e)}")
            return False

    async def _attempt_reconnection(self) -> None:
        """محاولة إعادة الاتصال بـ Redis"""
        for attempt in range(self.config['max_retries']):
            try:
                await self.init_redis()
                if self.redis:
                    logging.info("Successfully reconnected to Redis")
                    return
            except Exception as e:
                logging.error(f"Reconnection attempt {attempt + 1} failed: {str(e)}")
                await asyncio.sleep(2 ** attempt)

    async def _monitor_resource_usage(self) -> None:
        """مراقبة استخدام الموارد"""
        try:
            # مراقبة الذاكرة
            memory_info = psutil.Process().memory_info()
            self.metrics['memory_usage'].labels(
                type='rss'
            ).set(memory_info.rss)
            self.metrics['memory_usage'].labels(
                type='vms'
            ).set(memory_info.vms)

            # مراقبة CPU
            cpu_percent = psutil.cpu_percent()
            self.metrics['resource_usage'].labels(
                resource_type='cpu'
            ).set(cpu_percent)

            # عدد المهام النشطة
            active_tasks = sum(
                1 for status in self._task_statuses.values()
                if status == TaskStatus.PROCESSING
            )
            self.metrics['active_tasks'].set(active_tasks)

        except Exception as e:
            logging.error(f"Error monitoring resources: {str(e)}")

    async def cleanup_old_data(self) -> None:
        """تنظيف البيانات القديمة"""
        try:
            # تنظيف Stream
            await self.redis.xtrim(self.stream_key, maxlen=1000)

            # تنظيف بيانات المهام القديمة
            current_time = datetime.now(timezone.utc)
            for task_number in range(1, 12):
                task_status = self._task_statuses.get(f'task{task_number}')
                if task_status in [TaskStatus.COMPLETED, TaskStatus.FAILED]:
                    await self.cleanup_task_data(task_number)

            # تنظيف الملفات المؤقتة
            await self._cleanup_temp_files()

            logging.info("Old data cleanup completed successfully")

        except Exception as e:
            logging.error(f"Error during cleanup: {str(e)}")

    async def _handle_timeout_error(self, error: Exception) -> None:
        """معالجة أخطاء المهلة الزمنية"""
        logging.error(f"Timeout error: {str(error)}")

        try:
            # تحرير الموارد
            await self._release_resources()

            # إعادة محاولة الاتصال أو التشغيل
            await self._attempt_reconnection()

            # تسجيل الخطأ
            await self._log_timeout_details(error)

        except Exception as e:
            logging.critical(f"Error handling timeout: {str(e)}")

    async def _release_resources(self) -> None:
        """تحرير الموارد عند حدوث خطأ في المهلة الزمنية"""
        try:
            # إطلاق السيمافورات
            for semaphore in self._task_semaphores.values():
                while semaphore._value < semaphore._bound_value:
                    semaphore.release()

            # تنظيف الذاكرة والمهام المؤقتة
            await self.cleanup_old_data()
        except Exception as e:
            logging.error(f"Resource release error: {str(e)}")

    async def _log_timeout_details(self, error: Exception) -> None:
        """تسجيل تفاصيل خطأ المهلة الزمنية"""
        try:
            timeout_details = {
                'error_type': 'timeout',
                'error_message': str(error),
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'traceback': traceback.format_exc()
            }

            await self.redis.hset(
                'timeout_errors',
                mapping=timeout_details
            )
        except Exception as e:
            logging.error(f"Error logging timeout details: {str(e)}")

    async def _cleanup_temp_files(self) -> None:
        """تنظيف الملفات المؤقتة"""
        try:
            current_time = datetime.now(timezone.utc)
            for root, dirs, files in os.walk('./temp'):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_time = datetime.fromtimestamp(
                        os.path.getmtime(file_path),
                        timezone.utc
                    )
                    if (current_time - file_time).total_seconds() > 3600:  # أقدم من ساعة
                        os.remove(file_path)
                        logging.info(f"Removed old temp file: {file_path}")
        except Exception as e:
            logging.error(f"Error cleaning temp files: {str(e)}")

    # واجهات API العامة
    async def validate_api_keys(
            self,
            google_api_key: str,
            eleven_labs_api_key: str,
            eleven_labs_voice_id: str
    ) -> bool:
        """التحقق من صلاحية المفاتيح من خلال محاولة استخدامها"""
        try:
            # التحقق من تنسيق المفاتيح
            if not await self._validate_api_key_format(google_api_key, 'google'):
                raise ValueError("Invalid Google API key format")
            if not await self._validate_api_key_format(eleven_labs_api_key, 'eleven_labs'):
                raise ValueError("Invalid Eleven Labs API key format")
            if not await self._validate_voice_id_format(eleven_labs_voice_id):
                raise ValueError("Invalid voice ID format")

            # اختبار مفتاح Google
            google_response = await self._test_google_api(google_api_key)
            if not google_response:
                raise ValueError("Invalid Google API key")

            # اختبار مفتاح Eleven Labs
            eleven_labs_response = await self._test_eleven_labs_api(
                eleven_labs_api_key,
                eleven_labs_voice_id
            )
            if not eleven_labs_response:
                raise ValueError("Invalid Eleven Labs credentials")

            return True

        except Exception as e:
            logging.error(f"API validation error: {str(e)}")
            return False

    async def configure_apis(self,
                             google_api_key: str,
                             eleven_labs_api_key: str,
                             eleven_labs_voice_id: str) -> None:
        """تكوين APIs مع التحقق من الصحة"""
        try:
            # التحقق من المفاتيح
            valid = await self.validate_api_keys(
                google_api_key,
                eleven_labs_api_key,
                eleven_labs_voice_id
            )
            if not valid:
                raise APIConfigurationError("API key validation failed")

            # تكوين Google Model
            genai.configure(api_key=google_api_key)
            self.google_model = genai.GenerativeModel('gemini-1.5-flash')

            # تكوين Eleven Labs
            self.eleven_labs_config = {
                'api_key': eleven_labs_api_key,
                'voice_id': eleven_labs_voice_id
            }

            # تشفير المفاتيح للتخزين المؤقت
            encrypted_keys = await self._encrypt_api_keys({
                'google': google_api_key,
                'eleven_labs': eleven_labs_api_key
            })

            # حفظ التكوين المشفر في Redis
            await self.redis.hset(
                'api_config',
                mapping=encrypted_keys
            )

            logging.info("APIs configured successfully")

        except Exception as e:
            logging.error(f"API configuration error: {str(e)}")
            raise APIConfigurationError(f"Failed to configure APIs: {str(e)}")

    async def chain_tasks(self, topic: str) -> None:
        """تنفيذ سلسلة المهام مع مرونة محسنة"""
        try:
            logging.info("Starting task chain")
            chain_status = {
                'start_time': datetime.now(timezone.utc),
                'completed_tasks': [],
                'failed_tasks': [],
                'skipped_tasks': []
            }

            # حجز الموارد للسلسلة
            resources_acquired = await self._acquire_chain_resources()
            if not resources_acquired:
                raise ResourceExhaustionError("Failed to acquire chain resources")

            try:
                # إنشاء مجموعة مهام متزامنة
                async with asyncio.TaskGroup() as tg:
                    for task_number in range(1, 12):
                        # التحقق من المتطلبات المسبقة
                        if not await self._check_prerequisites(task_number):
                            chain_status['skipped_tasks'].append(task_number)
                            logging.warning(f"Skipping task {task_number} due to unmet prerequisites")
                            continue

                        # تنفيذ المهمة
                        task_func = getattr(self, f'task_{task_number}_execute', None)
                        if task_func:
                            if await self._execute_task(task_number, task_func, topic):
                                chain_status['completed_tasks'].append(task_number)
                            else:
                                chain_status['failed_tasks'].append(task_number)
                                if not self._can_continue_after_failure(task_number):
                                    logging.error(f"Task chain stopped after task {task_number} failure")
                                    break

            finally:
                # تحرير الموارد
                await self._release_chain_resources()

            # تحديث حالة السلسلة النهائية
            chain_status['end_time'] = datetime.now(timezone.utc)
            chain_status['duration'] = (chain_status['end_time'] - chain_status['start_time']).total_seconds()

            await self._store_chain_status(chain_status)
            logging.info("Task chain completed")

        except Exception as e:
            logging.error(f"Task chain error: {str(e)}")
            await self._handle_chain_error(e)

    # إضافة الدوال المفقودة
    async def _handle_connection_error(self, error: Exception) -> None:
        """معالجة أخطاء الاتصال"""
        logging.error(f"Connection error: {str(error)}")
        await self._attempt_reconnection()

    async def _handle_validation_error(self, error: Exception) -> None:
        """معالجة أخطاء التحقق"""
        logging.error(f"Validation error: {str(error)}")
        await self._rollback_invalid_changes()

    async def _handle_resource_error(self, error: Exception) -> None:
        """معالجة أخطاء الموارد"""
        logging.error(f"Resource error: {str(error)}")
        await self._free_resources()

    async def _test_google_api(self, api_key: str) -> bool:
        """اختبار صلاحية Google API"""
        try:
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = await model.generate_content("Test")
            return bool(response and response.text)
        except Exception as e:
            logging.error(f"Google API test failed: {str(e)}")
            return False

    async def _test_eleven_labs_api(self, api_key: str, voice_id: str) -> bool:
        """اختبار صلاحية Eleven Labs API"""
        try:
            url = f"https://api.elevenlabs.io/v1/voices/{voice_id}"
            headers = {
                'xi-api-key': api_key,
                'accept': 'application/json'
            }
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers) as response:
                    return response.status == 200
        except Exception as e:
            logging.error(f"Eleven Labs API test failed: {str(e)}")
            return False

    async def _check_task_result(self, task_number: int, result: Dict) -> bool:
        """التحقق من نتيجة المهمة"""
        try:
            if not isinstance(result, dict):
                raise ValueError(f"Invalid result format for task {task_number}")

            required_fields = ['status', 'content', 'timestamp']
            missing_fields = [field for field in required_fields if field not in result]
            if missing_fields:
                raise ValueError(f"Missing required fields: {missing_fields}")

            if result['status'] != 'success':
                error_msg = result.get('message', 'Unknown error')
                logging.error(f"Task {task_number} failed: {error_msg}")
                self.metrics['task_errors'].labels(
                    task_number=str(task_number),
                    error_type=result.get('error_type', 'unknown')
                ).inc()
                await self._store_error_details(task_number, result)
                return False

            # حفظ النتيجة
            self._results[f'task{task_number}'].set_success(result['content'])
            logging.info(f"Task {task_number} completed successfully")
            return True

        except Exception as e:
            logging.error(f"Error checking task {task_number} result: {str(e)}")
            await self._handle_check_error(task_number, e)
            return False

    async def _update_task_status(self, task_number: int, status: TaskStatus) -> None:
        """تحديث حالة المهمة"""
        try:
            self._task_statuses[f'task{task_number}'] = status

            # تحديث في Redis
            await self.redis.hset(
                'task_status',
                f'task_{task_number}',
                status.value
            )

            # تحديث المقاييس
            if status == TaskStatus.PROCESSING:
                self.metrics['active_tasks'].inc()
            elif status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                self.metrics['active_tasks'].dec()

            logging.info(f"Task {task_number} status updated to {status.value}")

        except Exception as e:
            logging.error(f"Error updating task {task_number} status: {str(e)}")

    async def _rollback_invalid_changes(self) -> None:
        """التراجع عن التغييرات غير الصالحة"""
        try:
            # استرجاع النسخ الاحتياطية
            for task_number in range(1, 12):
                backup_key = f'task_{task_number}_backup'
                backup_data = await self.redis.get(backup_key)
                if backup_data:
                    self._results[f'task{task_number}'] = TaskResult.from_dict(json.loads(backup_data))
        except Exception as e:
            logging.error(f"Error rolling back changes: {str(e)}")

    async def _free_resources(self) -> None:
        """تحرير الموارد"""
        try:
            # تنظيف الذاكرة المؤقتة
            await self.cleanup_old_data()

            # تحرير السيمافورات
            for semaphore in self._task_semaphores.values():
                for _ in range(semaphore._bound_value - semaphore._value):
                    semaphore.release()

            # إغلاق الاتصالات
            if self.redis_manager:
                await self.redis_manager.cleanup()

        except Exception as e:
            logging.error(f"Error freeing resources: {str(e)}")

    async def _handle_check_error(self, task_number: int, error: Exception) -> None:
        """معالجة أخطاء التحقق من المهام"""
        error_details = {
            'task_number': task_number,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        await self._store_error_details(task_number, {'message': str(error)})
        logging.error(f"Check error for task {task_number}: {str(error)}")

    async def _check_prerequisites(self, task_number: int) -> bool:
        """التحقق من المتطلبات المسبقة للمهمة"""
        prerequisites = self._task_prerequisites.get(task_number, [])
        for prereq in prerequisites:
            if prereq == 8 and task_number in [9, 11]:
                continue
            if self._task_statuses.get(f'task{prereq}') != TaskStatus.COMPLETED:
                return False
        return True

    async def _execute_task(self, task_number: int, task_func: callable, *args) -> bool:
        """تنفيذ مهمة مع معالجة محسنة للحالات الاستثنائية"""
        try:
            # التحقق من صلاحية المهمة
            if not await self._validate_task_execution(task_number):
                return False

            # تحديث حالة المهمة إلى "قيد التنفيذ"
            await self._update_task_status(task_number, TaskStatus.PROCESSING)

            # حجز الموارد للمهمة
            if not await self._acquire_task_resources(task_number):
                raise ResourceExhaustionError(f"Failed to acquire resources for task {task_number}")

            try:
                # إعداد مهلة زمنية للتنفيذ
                timeout = ClientTimeout(total=self.config['timeout'])

                # تنفيذ المهمة مع مراقبة الوقت والموارد
                async with async_timeout.timeout(self.config['timeout']):
                    start_time = datetime.now()

                    # تنفيذ المهمة
                    result = await task_func(*args)

                    # حساب وقت التنفيذ
                    execution_time = (datetime.now() - start_time).total_seconds()

                    # تحديث قياسات الأداء
                    self.metrics['task_duration'].labels(
                        task_number=str(task_number)
                    ).observe(execution_time)

                    # التحقق من النتيجة
                    success = await self._check_task_result(task_number, result)

                    # تحديث الحالة النهائية
                    final_status = TaskStatus.COMPLETED if success else TaskStatus.FAILED
                    if task_number == 8 and not success:
                        final_status = TaskStatus.FAILED_CONTINUING

                    await self._update_task_status(task_number, final_status)

                    return success

            finally:
                # تحرير الموارد
                await self._release_task_resources(task_number)

        except asyncio.TimeoutError:
            logging.error(f"Task {task_number} timed out")
            await self._handle_timeout(task_number)
            return False

        except Exception as e:
            logging.error(f"Error executing task {task_number}: {str(e)}")
            await self._handle_execution_error(task_number, e)
            return False

    async def _validate_task_execution(self, task_number: int) -> bool:
        """التحقق من صلاحية تنفيذ المهمة"""
        try:
            # التحقق من المتطلبات المسبقة
            prerequisites = self._task_prerequisites.get(task_number, [])
            for prereq in prerequisites:
                if self._task_statuses.get(f'task{prereq}') != TaskStatus.COMPLETED:
                    logging.error(f"Task {prereq} must be completed before task {task_number}")
                    return False

            # التحقق من حالة المهمة
            current_status = self._task_statuses.get(f'task{task_number}')
            if current_status == TaskStatus.PROCESSING:
                logging.warning(f"Task {task_number} is already processing")
                return False

            return True

        except Exception as e:
            logging.error(f"Error validating task {task_number}: {str(e)}")
            return False

    async def _acquire_chain_resources(self) -> bool:
        """حجز الموارد للسلسلة"""
        try:
            # التحقق من توفر الذاكرة
            memory = psutil.virtual_memory()
            if memory.percent > 90:  # أكثر من 90% مستخدم
                raise ResourceExhaustionError("Insufficient memory")

            # التحقق من توفر CPU
            if psutil.cpu_percent() > 90:  # أكثر من 90% مستخدم
                raise ResourceExhaustionError("High CPU usage")

            return True

        except Exception as e:
            logging.error(f"Error acquiring chain resources: {str(e)}")
            return False

    async def _release_chain_resources(self) -> None:
        """تحرير موارد السلسلة"""
        try:
            # تنظيف الذاكرة المؤقتة
            await self.cleanup_old_data()

            # تحرير السيمافورات
            for semaphore in self._task_semaphores.values():
                while semaphore._value < semaphore._bound_value:
                    semaphore.release()

        except Exception as e:
            logging.error(f"Error releasing chain resources: {str(e)}")

        # تنفيذ المهام المحددة

    async def task_1_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 1: توليد المواضيع"""
        return await self.task_1_generate_youtube_shorts_topics(topic)

    async def task_2_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 2: تحليل الاتجاهات"""
        return await self.task_2_YouTube_Shorts_Analyse_Trends()

    async def task_3_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 3: تحسين المشاركة"""
        return await self.task_3_YouTube_Shorts_Improve_Audience_Engagement()

    async def task_4_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 4: كتابة النصوص"""
        return await self.task_4_YouTube_Shorts_Write_Scripts()

    async def task_5_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 5: بحث الكلمات المفتاحية"""
        return await self.task_5_SEO_keyword_research()

    async def task_6_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 6: كتابة الوصف"""
        return await self.task_6_YouTube_Shorts_Write_Description()

    async def task_7_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 7: اقتراح العنوان"""
        return await self.task_7_YouTube_Shorts_Suggest_SEO_Title()

    async def task_8_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 8: توليد الصوت"""
        return await self.task_8_generate_audio()

    async def task_9_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 9: إنشاء لوحة القصة"""
        return await self.task_9_Storyboard_Scenes()

    async def task_10_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 10: تحليل المشاهد"""
        return await self.task_10_image_Scenes()

    async def task_11_execute(self, topic: str) -> Dict:
        """تنفيذ المهمة 11: توليد الصور"""
        return await self.task_11_generate_images()

        # Cleanup methods

    async def cleanup_all_tasks(self) -> None:
        """تنظيف جميع المهام"""
        try:
            # تنظيف بيانات المهام
            for task_number in range(1, 12):
                await self.cleanup_task_data(task_number)

            # تنظيف البيانات المؤقتة
            await self.cleanup_old_data()

            # إغلاق اتصال Redis
            if self.redis_manager:
                await self.redis_manager.cleanup()

            logging.info("All tasks cleaned up successfully")

        except Exception as e:
            logging.error(f"Error during final cleanup: {str(e)}")

    async def cleanup_task_data(self, task_number: int) -> None:
        """تنظيف بيانات المهمة"""
        try:
            # التحقق من وجود Redis قبل محاولة التنظيف
            if not self.redis:
                return

            # تنظيف الملفات المؤقتة
            temp_dir = f'./temp/task_{task_number}'
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)

            # تنظيف بيانات Redis
            patterns = [
                f'task_{task_number}_*',
                f'temp_task_{task_number}_*'
            ]
            for pattern in patterns:
                try:
                    keys = await self.redis.keys(pattern)
                    if keys:
                        await self.redis.delete(*keys)
                except Exception as e:
                    logging.warning(f"Warning cleaning up keys for pattern {pattern}: {str(e)}")

            logging.info(f"Cleaned up data for task {task_number}")

        except Exception as e:
            logging.warning(f"Warning cleaning up task {task_number} data: {str(e)}")

    async def _handle_task_error(self, task_number: int, error: Exception) -> None:
        """معالجة أخطاء المهام"""
        error_details = {
            'task_number': task_number,
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'traceback': traceback.format_exc()
        }

        try:
            # تحديث حالة المهمة
            await self._update_task_status(task_number, TaskStatus.FAILED)

            # تسجيل الخطأ
            logging.error(f"Task {task_number} error: {str(error)}\n{traceback.format_exc()}")

            # تحديث المقاييس
            self.metrics['task_errors'].labels(
                task_number=str(task_number),
                error_type=error_details['error_type']
            ).inc()

            # تخزين تفاصيل الخطأ
            await self.redis.hset(
                f'task_{task_number}_error',
                mapping=error_details
            )

            # محاولة تنظيف الموارد
            await self.cleanup_task_data(task_number)

            # إرسال إشعار
            await self.stream_result(task_number, {
                'status': 'error',
                'error': error_details,
                'can_continue': self._can_continue_after_failure(task_number)
            })

        except Exception as e:
            logging.critical(f"Error handling task {task_number} failure: {str(e)}")

    async def _handle_timeout(self, task_number: int) -> None:
        """معالجة أخطاء المهلة"""
        await self._update_task_status(task_number, TaskStatus.FAILED)
        await self._store_error_details(task_number, {
            'message': 'Task timeout',
            'error_type': 'timeout'
        })
        await self.cleanup_task_data(task_number)

    async def _handle_execution_error(self, task_number: int, error: Exception) -> None:
        """معالجة أخطاء التنفيذ"""
        await self._handle_task_error(task_number, error)
        await self.cleanup_task_data(task_number)
        await self._monitor_resource_usage()

    async def _handle_chain_error(self, error: Exception) -> None:
        """معالجة أخطاء السلسلة"""
        error_details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'traceback': traceback.format_exc()
        }

        try:
            # تحديث حالة السلسلة
            await self.redis.hset(
                'chain_status',
                mapping={
                    'status_text': json.dumps({
                        'status': 'error',
                        'message': str(error),
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    })
                }
            )

            # تسجيل الخطأ
            logging.error(f"Chain error: {error_details}")

            # تنظيف الموارد
            await self._cleanup_resources()

        except Exception as e:
            logging.critical(f"Error handling chain failure: {str(e)}")

    # وظائف مساعدة للمهام
    async def _store_error_details(self, task_number: int, error_info: Dict) -> None:
        """تخزين تفاصيل الخطأ"""
        try:
            error_details = {
                'task_number': task_number,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                **error_info
            }
            await self.redis.hset(
                f'task_{task_number}_error',
                mapping=error_details
            )
        except Exception as e:
            logging.error(f"Error storing error details: {str(e)}")

    async def _store_chain_status(self, status: Dict) -> None:
        """تخزين حالة السلسلة"""
        try:
            await self.redis.hset(
                'chain_status',
                mapping={
                    'status': json.dumps(status),
                    'last_update': datetime.now(timezone.utc).isoformat()
                }
            )
        except Exception as e:
            logging.error(f"Error storing chain status: {str(e)}")

    # وظائف مساعدة للموارد
    async def _acquire_task_resources(self, task_number: int) -> bool:
        """حجز موارد المهمة"""
        try:
            if task_number == 8:  # مهمة الصوت
                async with async_timeout.timeout(10):
                    await self._task_semaphores['audio'].acquire()
            elif task_number in [9, 10, 11]:  # مهام الصور
                async with async_timeout.timeout(10):
                    await self._task_semaphores['image'].acquire()
            return True
        except Exception as e:
            logging.error(f"Failed to acquire resources for task {task_number}: {str(e)}")
            return False

    async def _release_task_resources(self, task_number: int) -> None:
        """تحرير موارد المهمة"""
        try:
            if task_number == 8:
                self._task_semaphores['audio'].release()
            elif task_number in [9, 10, 11]:
                self._task_semaphores['image'].release()
        except Exception as e:
            logging.error(f"Error releasing resources for task {task_number}: {str(e)}")

    # وظائف المراقبة والتسجيل
    async def get_task_status(self, task_number: int) -> Dict:
        """الحصول على حالة المهمة"""
        try:
            status = self._task_statuses.get(f'task{task_number}')
            result = self._results.get(f'task{task_number}')

            return {
                'task_number': task_number,
                'status': status.value if status else 'unknown',
                'result': result.to_dict() if result else None
            }
        except Exception as e:
            logging.error(f"Error getting task {task_number} status: {str(e)}")
            return {
                'task_number': task_number,
                'status': 'error',
                'error': str(e)
            }

    async def get_chain_status(self) -> Dict:
        """الحصول على حالة السلسلة"""
        try:
            status_raw = await self.redis.hget('chain_status', 'status')
            if status_raw:
                return json.loads(status_raw)
            return {
                'status': 'unknown',
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        except Exception as e:
            logging.error(f"Error getting chain status: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    # وظائف التشفير والأمان
    async def _encrypt_api_keys(self, keys: Dict[str, str]) -> Dict[str, str]:
        """تشفير مفاتيح API"""
        try:
            key = Fernet.generate_key()
            f = Fernet(key)
            # تخزين مفتاح التشفير بشكل آمن
            await self.redis.set('encryption_key', key.decode())
            return {k: f.encrypt(v.encode()).decode() for k, v in keys.items()}
        except Exception as e:
            logging.error(f"Error encrypting API keys: {str(e)}")
            raise

    async def _decrypt_api_keys(self, encrypted_keys: Dict[str, str]) -> Dict[str, str]:
        """فك تشفير مفاتيح API"""
        try:
            key = await self.redis.get('encryption_key')
            if not key:
                raise ValueError("Encryption key not found")
            f = Fernet(key.encode())
            return {k: f.decrypt(v.encode()).decode() for k, v in encrypted_keys.items()}
        except Exception as e:
            logging.error(f"Error decrypting API keys: {str(e)}")
            raise

    # وظائف التنظيف والتحكم في الموارد
    async def _cleanup_resources(self) -> None:
        """تنظيف الموارد"""
        try:
            # تنظيف المهام
            for task_number in range(1, 12):
                await self.cleanup_task_data(task_number)

            # تنظيف البيانات المؤقتة
            await self.cleanup_old_data()

            # إغلاق اتصالات Redis
            if self.redis_manager:
                await self.redis_manager.cleanup()

            # تنظيف المجلدات المؤقتة
            shutil.rmtree('./temp', ignore_errors=True)
            os.makedirs('./temp')
            os.makedirs('./temp/audio')
            os.makedirs('./temp/images')

        except Exception as e:
            logging.error(f"Error cleaning up resources: {str(e)}")

    # وظائف مساعدة للتحقق من البيانات
    async def _validate_api_key_format(self, api_key: str, service: str) -> bool:
        """التحقق من تنسيق مفتاح API"""
        patterns = {
            'google': r'^AIza[0-9A-Za-z-_]{35}$',
            'eleven_labs': r'^[0-9a-f]{32}$'
        }
        return bool(re.match(patterns.get(service, ''), api_key))

    async def _validate_voice_id_format(self, voice_id: str) -> bool:
        """التحقق من تنسيق معرف الصوت"""
        return bool(re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', voice_id))

    def _can_continue_after_failure(self, task_number: int) -> bool:
        """تحديد إمكانية الاستمرار بعد فشل المهمة"""
        critical_tasks = [1, 4]  # المهام الحرجة
        return task_number not in critical_tasks

    # وظائف مساعدة للمهام
    async def _get_safe_task_result(self, task_number: int, key: str = None) -> Optional[Any]:
        """استرجاع نتيجة المهمة بشكل آمن"""
        try:
            result = self._results.get(f'task{task_number}')
            if not result:
                return None

            content = result.content
            if not content:
                return None

            if key and isinstance(content, dict):
                return content.get(key)

            return content

        except Exception as e:
            logging.error(f"Error retrieving task {task_number} result: {str(e)}")
            return None

    async def task_1_generate_youtube_shorts_topics(self, topic: str) -> Dict:
        """توليد مواضيع YouTube Shorts"""
        try:
            if not self.google_model:
                raise ValueError("Google Model not initialized")

            logging.info(f"Starting topic generation for: {topic}")
            start_time = datetime.now()

            formatted_prompt = task_1_prompt.format(topic=topic)
            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            # حفظ النتيجة في Redis للاستخدام المستقبلي
            await self.redis.setex(
                'task_1_result',
                3600,  # تنتهي صلاحيتها بعد ساعة
                json.dumps({'content': text_response})
            )

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Topic generation completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in topic generation: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_2_YouTube_Shorts_Analyse_Trends(self) -> Dict:
        """تحليل اتجاهات YouTube Shorts"""
        try:
            if not self.google_model:
                raise ValueError("Google Model not initialized")

            task1_result = await self._get_safe_task_result(1)
            if not task1_result:
                raise ValueError("Task 1 result not found")

            logging.info("Starting trends analysis")
            start_time = datetime.now()

            formatted_prompt = task_2_prompt.format(niche=task1_result)
            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            # حفظ النتيجة
            await self.redis.setex(
                'task_2_result',
                3600,
                json.dumps({'content': text_response})
            )

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Trends analysis completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in trends analysis: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_3_YouTube_Shorts_Improve_Audience_Engagement(self) -> Dict:
        """تحسين مشاركة الجمهور"""
        try:
            task2_result = await self._get_safe_task_result(2)
            if not task2_result:
                raise ValueError("Task 2 result not found")

            logging.info("Starting audience engagement improvement")
            start_time = datetime.now()

            formatted_prompt = task_3_prompt.format(
                Analyse_Trends=task2_result
            )

            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Audience engagement improvement completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in audience engagement improvement: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_4_YouTube_Shorts_Write_Scripts(self) -> Dict:
        """كتابة النصوص"""
        try:
            task2_result = await self._get_safe_task_result(2)
            task3_result = await self._get_safe_task_result(3)
            if not task2_result or not task3_result:
                raise ValueError("Required task results not found")

            logging.info("Starting script writing")
            start_time = datetime.now()

            formatted_prompt = task_4_prompt.format(
                Analyse_Trends=task2_result,
                Engagement=task3_result
            )

            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Script writing completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in script writing: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_5_SEO_keyword_research(self) -> Dict:
        """بحث الكلمات المفتاحية SEO"""
        try:
            task1_result = await self._get_safe_task_result(1)
            task2_result = await self._get_safe_task_result(2)
            task4_result = await self._get_safe_task_result(4)

            if not all([task1_result, task2_result, task4_result]):
                raise ValueError("Required task results not found")

            logging.info("Starting SEO keyword research")
            start_time = datetime.now()

            formatted_prompt = task_5_prompt.format(
                niche=task1_result,
                Analyse_Trends=task2_result,
                Script=task4_result
            )

            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"SEO keyword research completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in SEO keyword research: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_6_YouTube_Shorts_Write_Description(self) -> Dict:
        """كتابة وصف الفيديو"""
        try:
            task2_result = await self._get_safe_task_result(2)
            task4_result = await self._get_safe_task_result(4)
            task5_result = await self._get_safe_task_result(5)

            if not all([task2_result, task4_result, task5_result]):
                raise ValueError("Required task results not found")

            logging.info("Starting description writing")
            start_time = datetime.now()

            formatted_prompt = task_6_prompt.format(
                Analyse_Trends=task2_result,
                Script=task4_result,
                keyword=task5_result
            )

            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Description writing completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in description writing: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_7_YouTube_Shorts_Suggest_SEO_Title(self) -> Dict:
        """اقتراح عنوان SEO"""
        try:
            task2_result = await self._get_safe_task_result(2)
            task4_result = await self._get_safe_task_result(4)
            task5_result = await self._get_safe_task_result(5)

            if not all([task2_result, task4_result, task5_result]):
                raise ValueError("Required task results not found")

            logging.info("Starting SEO title suggestion")
            start_time = datetime.now()

            formatted_prompt = task_7_prompt.format(
                Analyse_Trends=task2_result,
                Script=task4_result,
                keyword=task5_result
            )

            response = await self.google_model.generate_content(formatted_prompt)
            text_response = response.text

            if not text_response:
                raise ValueError("Invalid response received from Google Model")

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"SEO title suggestion completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': text_response,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in SEO title suggestion: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    # إضافة الدالة المفقودة لتوليد الصوت
    async def _generate_audio_external(self, script_content: str) -> bytes:
        """توليد الصوت عبر Eleven Labs API"""
        try:
            if not self.eleven_labs_config:
                raise ValueError("Eleven Labs not configured")

            voice_id = self.eleven_labs_config['voice_id']
            api_key = self.eleven_labs_config['api_key']

            # التحقق من حجم النص
            if len(script_content) > 5000:  # حد Eleven Labs
                raise ValueError("Script content too long")

            async with aiohttp.ClientSession() as session:
                url = f"https://api.elevenlabs.io/v1/text-to-speech/{voice_id}"
                headers = {
                    "xi-api-key": api_key,
                    "Content-Type": "application/json",
                }
                payload = {
                    "text": script_content,
                    "model_id": "eleven_multilingual_v2",
                    "voice_settings": {
                        "stability": 0.5,
                        "similarity_boost": 0.5,
                        "style": 1.0,
                        "use_speaker_boost": True
                    }
                }

                async with session.post(url, headers=headers, json=payload, timeout=120) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise ValueError(f"Audio generation failed: {error_text}")

                    audio_data = await response.read()
                    if len(audio_data) > MAX_AUDIO_SIZE:
                        raise ValueError(f"Generated audio too large: {len(audio_data)} bytes")

                    return audio_data

        except asyncio.TimeoutError:
            raise TimeoutError("Audio generation timed out")
        except Exception as e:
            logging.error(f"Error in audio generation: {str(e)}")
            raise

    async def task_8_generate_audio(self) -> Dict:
        """توليد الصوت"""
        try:
            task4_result = await self._get_safe_task_result(4)
            if not task4_result:
                raise ValueError("Task 4 result not found")

            if not self.eleven_labs_config:
                raise ValueError("Eleven Labs not configured")

            logging.info("Starting audio generation")
            start_time = datetime.now()

            # توليد الصوت مع إدارة الأخطاء
            audio_data = await self._generate_audio_with_retries(task4_result)

            # تحليل الصوت
            audio = AudioSegment.from_mp3(BytesIO(audio_data))
            audio_duration = len(audio) / 1000.0

            # تحديد الأبعاد
            dimensions = (
                "width=1080&height=1920"
                if audio_duration <= 60
                else "width=1920&height=1080"
            )

            # إنشاء البيانات الوصفية
            metadata = {
                'duration': audio_duration,
                'dimensions': dimensions,
                'format': 'mp3',
                'channels': audio.channels,
                'frame_rate': audio.frame_rate,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

            # حفظ البيانات الوصفية
            await self._store_audio_metadata(metadata)

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Audio generation completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': metadata,
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'external_audio_id': str(uuid.uuid4())
            }

        except Exception as e:
            error_msg = f"Error in audio generation: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_9_Storyboard_Scenes(self) -> Dict:
        """إنشاء لوحة القصة"""
        try:
            task4_result = await self._get_safe_task_result(4)
            task8_metadata = await self._get_audio_metadata()

            if not task4_result:
                raise ValueError("Task 4 result not found")

            logging.info("Starting storyboard creation")
            start_time = datetime.now()

            # حساب عدد المشاهد المثالي
            scene_count = await self._calculate_optimal_scene_count(task8_metadata)

            formatted_prompt = task_9_prompt.format(
                Script=task4_result,
                secend=scene_count
            )

            response = await self.google_model.generate_content(formatted_prompt)

            # تحليل وتنظيف الاستجابة
            scene_data = await self._parse_scene_response(response.text)

            # إضافة البيانات الوصفية
            for scene in scene_data['sentiments']:
                scene['metadata'] = {
                    'audio_duration': task8_metadata.get('duration') if task8_metadata else DEFAULT_AUDIO_DURATION,
                    'scene_duration': (task8_metadata.get('duration',
                                                          DEFAULT_AUDIO_DURATION) / scene_count) if scene_count > 0 else DEFAULT_AUDIO_DURATION,
                    'dimensions': task8_metadata.get('dimensions', DEFAULT_VIDEO_DIMENSIONS)
                }

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Storyboard creation completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': scene_data,
                'duration': duration,
                'metadata': {
                    'scene_count': scene_count,
                    'audio_duration': task8_metadata.get('duration') if task8_metadata else DEFAULT_AUDIO_DURATION,
                    'dimensions': task8_metadata.get('dimensions', DEFAULT_VIDEO_DIMENSIONS)
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in storyboard creation: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def task_10_image_Scenes(self) -> Dict:
        """تحليل مشاهد الصور"""
        try:
            task9_result = await self._get_safe_task_result(9)
            if not task9_result or 'sentiments' not in task9_result:
                raise ValueError("Invalid task 9 result")

            logging.info("Starting image scene analysis")
            start_time = datetime.now()

            scenes = task9_result['sentiments']

            # معالجة المشاهد بالتوازي
            async with asyncio.TaskGroup() as tg:
                tasks = [
                    tg.create_task(
                        self._process_single_scene(scene, self._task_semaphores['image'])
                    )
                    for scene in scenes
                ]
                results = [task.result() for task in tasks if task.result() is not None]

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Image scene analysis completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': {
                    'scenes': results,
                    'total_scenes': len(results),
                    'failed_scenes': len(scenes) - len(results)
                },
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in image scene analysis: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def _process_single_scene(self, scene: Dict, semaphore: asyncio.Semaphore) -> Optional[Dict]:
        """معالجة مشهد واحد مع التحكم في التزامن"""
        async with semaphore:
            for attempt in range(MAX_RETRIES_PER_SCENE):
                try:
                    if not isinstance(scene, dict) or 'scene_description' not in scene:
                        raise ValueError("Invalid scene data")

                    prompt = task_10_prompt.format(
                        storyline_content=scene['scene_description']
                    )

                    response = await self.google_model.generate_content(prompt)
                    text_response = response.text.strip()

                    if not text_response:
                        raise ValueError("Empty scene description")

                    return {
                        'scene_number': scene.get('scene_number', 0),
                        'original_description': scene['scene_description'],
                        'detailed_description': text_response,
                        'timestamp': datetime.now(timezone.utc).isoformat()
                    }

                except Exception as e:
                    if attempt == MAX_RETRIES_PER_SCENE - 1:
                        logging.error(f"Failed to process scene: {str(e)}")
                        return None
                    await asyncio.sleep(2 ** attempt)

    async def task_11_generate_images(self) -> Dict:
        """توليد الصور"""
        try:
            task10_result = await self._get_safe_task_result(10)
            task8_metadata = await self._get_audio_metadata()

            if not task10_result or 'scenes' not in task10_result['content']:
                raise ValueError("Invalid task 10 result")

            logging.info("Starting image generation")
            start_time = datetime.now()

            scenes = task10_result['content']['scenes']
            total_duration = task8_metadata.get('duration', DEFAULT_AUDIO_DURATION)
            scene_duration = total_duration / len(scenes) if scenes else DEFAULT_AUDIO_DURATION

            async with asyncio.TaskGroup() as tg:
                tasks = [
                    tg.create_task(self._generate_scene_images(scene, total_duration))
                    for scene in scenes
                ]
                processed_scenes = [task.result() for task in tasks if task.result() is not None]

            duration = (datetime.now() - start_time).total_seconds()
            logging.info(f"Image generation completed in {duration:.2f} seconds")

            return {
                'status': 'success',
                'content': {
                    'scenes': processed_scenes,
                    'metadata': {
                        'total_duration': total_duration,
                        'scene_duration': scene_duration,
                        'dimensions': task8_metadata.get('dimensions', DEFAULT_VIDEO_DIMENSIONS)
                    }
                },
                'duration': duration,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            error_msg = f"Error in image generation: {str(e)}"
            logging.error(error_msg)
            return {
                'status': 'error',
                'message': error_msg,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

    async def _generate_scene_images(self, scene: Dict, total_duration: float) -> Optional[Dict]:
        """توليد صور لمشهد واحد"""
        try:
            if not isinstance(scene, dict) or 'detailed_description' not in scene:
                raise ValueError("Invalid scene data")

            # تحسين النص للصورة
            image_prompt = await self._promptify(scene['detailed_description'])
            seed = random.randint(10000, 99999)

            # توليد روابط الصور بأحجام مختلفة
            image_urls = {
                'preview': f"https://image.pollinations.ai/prompt/{quote(image_prompt)}?width=512&height=512&nologo=poll&nofeed=yes&model=Flux&seed={seed}",
                'display': f"https://image.pollinations.ai/prompt/{quote(image_prompt)}?width=1024&height=1024&nologo=poll&nofeed=yes&model=Flux&seed={seed}",
                'hd': f"https://image.pollinations.ai/prompt/{quote(image_prompt)}?width=1920&height=1080&nologo=poll&nofeed=yes&model=Flux&seed={seed}"
            }

            return {
                'scene_number': scene.get('scene_number', 0),
                'description': scene['detailed_description'],
                'image_prompt': image_prompt,
                'images': image_urls,
                'timing': {
                    'start': (scene.get('scene_number', 0) - 1) * (total_duration / len(image_urls)),
                    'duration': total_duration / len(image_urls)
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }

        except Exception as e:
            logging.error(f"Error generating scene images: {str(e)}")
            return None

        # Helper Functions for Tasks

    async def _calculate_optimal_scene_count(self, audio_metadata: Optional[Dict] = None) -> int:
        """حساب العدد الأمثل للمشاهد"""
        if not audio_metadata:
            return DEFAULT_SCENE_COUNT

        duration = audio_metadata.get('duration', DEFAULT_AUDIO_DURATION)

        # حساب عدد المشاهد المثالي (مشهد كل 4 ثوانٍ تقريباً)
        scene_count = max(4, min(24, round(duration / 4)))

        return scene_count

    async def _parse_scene_response(self, response_text: str) -> Dict:
        """تحليل استجابة المشاهد"""
        try:
            # تنظيف النص
            clean_text = re.sub(r'^```(json)?|```$', '', response_text)
            clean_text = re.sub(r'\s+', ' ', clean_text.strip())

            # محاولة تحليل JSON
            scene_data = json.loads(clean_text)

            if 'sentiments' not in scene_data:
                raise ValueError("Missing 'sentiments' key")

            return scene_data

        except json.JSONDecodeError as e:
            logging.error(f"JSON parsing error: {str(e)}")
            raise ValueError("Invalid JSON format in scene data")
        except Exception as e:
            logging.error(f"Scene response parsing error: {str(e)}")
            raise

    async def _generate_audio_with_retries(self, script_content: str) -> bytes:
        """توليد الصوت مع إعادة المحاولة"""
        for attempt in range(MAX_RETRIES):
            try:
                return await self._generate_audio_external(script_content)
            except Exception as e:
                if attempt == MAX_RETRIES - 1:
                    raise
                logging.warning(f"Audio generation attempt {attempt + 1} failed: {str(e)}")
                await asyncio.sleep(2 ** attempt)

    async def _promptify(self, prompt: str) -> str:
        """تحسين النص لتوليد الصور"""
        components = {
            'image_type': "Realistic",
            'colors': "natural colors",
            'backgrounds': "minimalist background",
            'quality': "high quality, detailed",
            'style': "professional photography",
        }

        return f"{components['image_type']} {prompt}, {components['colors']}, {components['backgrounds']}, {components['quality']}, {components['style']}"

    async def _store_audio_metadata(self, metadata: Dict) -> None:
        """تخزين البيانات الوصفية للصوت"""
        try:
            await self.redis.hset(
                'task_8_metadata',
                mapping=metadata
            )
            await self.redis.expire('task_8_metadata', 3600)  # تنتهي الصلاحية بعد ساعة
        except Exception as e:
            logging.error(f"Error storing audio metadata: {str(e)}")

    async def _get_audio_metadata(self) -> Optional[Dict]:
        """استرجاع البيانات الوصفية للصوت"""
        try:
            metadata = await self.redis.hgetall('task_8_metadata')
            return metadata if metadata else None
        except Exception as e:
            logging.error(f"Error retrieving audio metadata: {str(e)}")
            return None


