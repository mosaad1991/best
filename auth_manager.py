import os
import logging
import json
import traceback
import bcrypt
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from jose import JWTError, jwt
from pydantic import BaseModel

from redis_manager import EnhancedRedisManager
from custom_exceptions import AuthenticationError

logger = logging.getLogger(__name__)

class Token(BaseModel):
    """نموذج التوكن"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int

class UserInDB(BaseModel):
    """نموذج المستخدم في قاعدة البيانات"""
    username: str
    hashed_password: str
    scopes: List[str] = []
    disabled: bool = False

class AuthConfig:
    """تكوينات المصادقة"""
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

class AuthManager:
    """مدير المصادقة والأمان"""

    def __init__(self, redis_manager: EnhancedRedisManager):
        """تهيئة مدير المصادقة"""
        if not redis_manager or not redis_manager.instances:
            raise ValueError("Redis manager with active connections is required")

        self.redis_manager = redis_manager

    def get_password_hash(self, password: str) -> str:
        """تشفير كلمة المرور"""
        try:
            if not password:
                raise ValueError("كلمة المرور فارغة")

            # تحويل كلمة المرور إلى bytes وتشفيرها
            password_bytes = password.encode('utf-8')
            hashed = bcrypt.hashpw(password_bytes, bcrypt.gensalt(12))
            return hashed.decode('utf-8')
        except Exception as e:
            logging.error(f"خطأ في تشفير كلمة المرور: {str(e)}")
            raise

    async def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """التحقق من كلمة المرور"""
        try:
            # تحويل كلمة المرور إلى bytes
            plain_password_bytes = plain_password.encode('utf-8')
            hashed_password_bytes = hashed_password.encode('utf-8')

            # التحقق المباشر باستخدام bcrypt
            return bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)
        except Exception as e:
            logging.error(f"خطأ في التحقق من كلمة المرور: {str(e)}")
            return False

    # دالة مساعدة للتحقق اليدوي
    def manual_password_check(username: str, plain_password: str, hashed_password: str):
        """
        دالة للتحقق اليدوي من كلمة المرور
        تستخدم للتصحيح والاختبار
        """
        print("=== التحقق اليدوي من كلمة المرور ===")
        print(f"اسم المستخدم: {username}")
        print(f"كلمة المرور الأصلية: {plain_password}")

        # محاولات التحقق المختلفة
        attempts = [
            plain_password,
            plain_password.strip(),
            plain_password.rstrip('0'),
            plain_password.lstrip('0')
        ]

        for attempt in attempts:
            print(f"\nمحاولة التحقق: {attempt}")
            try:
                plain_password_bytes = attempt.encode('utf-8')
                hashed_password_bytes = hashed_password.encode('utf-8')

                is_valid = bcrypt.checkpw(plain_password_bytes, hashed_password_bytes)
                print(f"نتيجة التحقق: {is_valid}")

                if is_valid:
                    return True
            except Exception as e:
                print(f"خطأ في المحاولة: {str(e)}")

        print("فشل جميع محاولات التحقق")
        return False

    async def get_user(self, username: str) -> Optional[UserInDB]:
        """استرجاع معلومات المستخدم مع التعامل مع الأخطاء"""
        try:
            # الحصول على العميل الحالي
            clients = await self.redis_manager.get_current_clients()
            redis_client = clients['text']

            logger.info(f"محاولة استرجاع المستخدم: {username}")

            # البحث عن المستخدم
            user_data = await redis_client.hgetall(f"user:{username}")
            
            logger.info("بيانات المستخدم التفصيلية:")
            for key, value in user_data.items():
                logger.info(f"{key}: {value}")

            # التحقق من وجود المستخدم
            if not user_data:
                logger.warning(f"لم يتم العثور على المستخدم: {username}")
                return None

            # معالجة نطاقات الصلاحيات بشكل أكثر مرونة
            scopes_str = user_data.get('scopes', '[]')
            try:
                # محاولة تحويل النطاقات من JSON
                scopes = json.loads(scopes_str) if scopes_str else []
            except (json.JSONDecodeError, TypeError):
                # استخدام النص مباشرة إذا فشل التحويل
                scopes = [scopes_str] if scopes_str else []

            # التحقق من وجود كلمة المرور المشفرة
            hashed_password = user_data.get('hashed_password', '')
            if not hashed_password:
                logger.error(f"لا توجد كلمة مرور مشفرة للمستخدم: {username}")
                return None

            # إنشاء كائن المستخدم
            user = UserInDB(
                username=username,
                hashed_password=hashed_password,
                scopes=scopes,
                disabled=bool(int(user_data.get('disabled', '0')))
            )

            logger.info("تم استرجاع المستخدم بنجاح")
            return user

        except Exception as e:
            # تسجيل أي أخطاء تحدث أثناء استرجاع المستخدم
            logger.error(f"خطأ في استرجاع بيانات المستخدم {username}: {str(e)}")
            logger.error(f"التفاصيل الكاملة للخطأ: {traceback.format_exc()}")
            return None

    async def authenticate_user(self, username: str, password: str) -> Optional[UserInDB]:
        """مصادقة المستخدم"""
        try:
            # استرجاع المستخدم
            user = await self.get_user(username)
            if not user:
                logging.warning(f"المستخدم غير موجود: {username}")
                return None

            # التحقق من تعطيل الحساب
            if user.disabled:
                logging.warning(f"الحساب معطل: {username}")
                raise AuthenticationError("الحساب معطل")

            # التحقق من كلمة المرور
            is_valid = await self.verify_password(password, user.hashed_password)
            if not is_valid:
                logging.warning(f"كلمة المرور غير صحيحة للمستخدم: {username}")
                return None

            return user
        except Exception as e:
            logging.error(f"خطأ في المصادقة: {str(e)}")
            return None

    # باقي الدوال تبقى كما هي دون تغيير
    async def create_tokens(self, user: UserInDB) -> Token:
        """إنشاء التوكن"""
        access_token_expires = timedelta(minutes=AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await self.create_access_token(
            data={"sub": user.username, "scopes": user.scopes},
            expires_delta=access_token_expires
        )

        refresh_token_expires = timedelta(days=AuthConfig.REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_token = await self.create_refresh_token(
            data={"sub": user.username},
            expires_delta=refresh_token_expires
        )

        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES * 60
        )

    async def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """إنشاء توكن الوصول"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)

        to_encode.update({"exp": expire, "type": "access"})
        encoded_jwt = jwt.encode(
            to_encode,
            AuthConfig.SECRET_KEY,
            algorithm=AuthConfig.ALGORITHM
        )
        return encoded_jwt

    async def create_refresh_token(self, data: dict, expires_delta: Optional[timedelta] = None) -> str:
        """إنشاء توكن التحديث"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(days=7)

        to_encode.update({"exp": expire, "type": "refresh"})
        encoded_jwt = jwt.encode(
            to_encode,
            AuthConfig.SECRET_KEY,
            algorithm=AuthConfig.ALGORITHM
        )
        return encoded_jwt

    async def validate_token(self, token: str, token_type: str = "access") -> dict:
        """التحقق من صحة التوكن"""
        try:
            payload = jwt.decode(
                token,
                AuthConfig.SECRET_KEY,
                algorithms=[AuthConfig.ALGORITHM]
            )
            if payload.get("type") != token_type:
                raise AuthenticationError("Invalid token type")
            return payload
        except JWTError:
            raise AuthenticationError("Invalid token")