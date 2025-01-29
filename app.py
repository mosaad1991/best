# FastAPI Imports
from fastapi import (
    FastAPI, HTTPException, BackgroundTasks,
    Request, Response, Depends, Header,
    Security, status
)
from fastapi.security import (
    OAuth2PasswordBearer, OAuth2PasswordRequestForm,
    SecurityScopes, HTTPBearer, HTTPAuthorizationCredentials
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from fastapi import Query
from fastapi import Body
from fastapi import FastAPI, HTTPException

# Starlette Imports
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.authentication import (
    AuthenticationBackend, AuthCredentials,
    BaseUser, SimpleUser, UnauthenticatedUser
)
from auth_manager import AuthManager
from custom_exceptions import AuthenticationError, ValidationError, PermissionError, ResourceNotFoundError

# Pydantic & Types
from pydantic import BaseModel, ValidationError, Field, validator, field_validator
from typing import Optional, Dict, Any, List, Union, Tuple

# Redis
import redis.asyncio as redis
from redis.asyncio.retry import Retry
from redis.exceptions import (
    ConnectionError, TimeoutError, RedisError,
    AuthenticationError, WatchError
)

# System & Environment
import os
import logging
import json
import asyncio
import traceback
import uuid
import base64
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from pathlib import Path
import tempfile
import shutil
import psutil
import time
import aiohttp
import multiprocessing
import socket

# Monitoring & Performance
from prometheus_client import multiprocess
from prometheus_client import (
    Counter, Histogram, Gauge, Summary,
    generate_latest, CollectorRegistry
)
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

# Security
from jose import JWTError, jwt
from passlib.context import CryptContext
from cryptography.fernet import Fernet
from secrets import token_urlsafe

# File Handling
from io import BytesIO, IOBase
import aiofiles

# Custom Imports
from core_logic import AsyncStreamingCoreLogic, APIConfigurationError
from config import (
    Settings, get_settings,
    SECURITY_CONFIG,
    MONITORING_CONFIG
)
from redis_manager import EnhancedRedisManager, RedisServiceName
from worker_manager import WorkerManager
from routes import router as api_router
from middleware import (
    WorkerMiddleware,
    TimeoutMiddleware,
    LoggingMiddleware,
    ErrorHandlingMiddleware
)


PROMETHEUS_DIR = os.getenv('PROMETHEUS_MULTIPROC_DIR', '/tmp/prometheus')
Path(PROMETHEUS_DIR).mkdir(parents=True, exist_ok=True)


load_dotenv(override=True)

# Custom Exceptions
class CustomError(Exception):
    """قاعدة للأخطاء المخصصة"""

    def __init__(self, message: str, status_code: int = 500, detail: Optional[str] = None):
        self.message = message
        self.status_code = status_code
        self.detail = detail
        super().__init__(self.message)

class ServiceConfigError(CustomError):
    """خطأ في تكوين الخدمة"""
    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message, status_code=500, detail=detail)


class APIConfigurationError(CustomError):
    """خطأ في تكوين API"""

    def __init__(self, message: str, detail: Optional[str] = None):
        super().__init__(message, status_code=500, detail=detail)


class AuthenticationError(CustomError):
    """خطأ في المصادقة"""

    def __init__(self, message: str = "Authentication failed", detail: Optional[str] = None):
        super().__init__(message, status_code=401, detail=detail)


class ValidationError(CustomError):
    """خطأ في التحقق من الصحة"""

    def __init__(self, message: str = "Validation error", detail: Optional[str] = None):
        super().__init__(message, status_code=422, detail=detail)

class PermissionError(CustomError):
    """خطأ في الصلاحيات"""

    def __init__(self, message: str = "Insufficient permissions", detail: Optional[str] = None):
        super().__init__(message, status_code=403, detail=detail)


class ResourceNotFoundError(CustomError):
    """خطأ عدم وجود المورد"""

    def __init__(self, message: str = "Resource not found", detail: Optional[str] = None):
        super().__init__(message, status_code=404, detail=detail)




REGISTRY = CollectorRegistry()
if os.environ.get('PROMETHEUS_MULTIPROC_DIR'):
    multiprocess.MultiProcessCollector(REGISTRY)

# تحديد RESOURCE_USAGE
RESOURCE_USAGE = Gauge(
    'resource_usage_percent',
    'Resource usage percentage',
    ['resource_type'],
    registry=REGISTRY
)


# Monitoring configuration
REQUEST_COUNT = Counter(
    'http_requests_total',
    'Total HTTP requests',
    registry=REGISTRY,
    labelnames=['method', 'endpoint', 'status'],


)
REQUEST_LATENCY = Histogram(
    'http_request_duration_seconds',
    'HTTP request latency',
    registry=REGISTRY,
    labelnames=['method', 'endpoint'],

)

TASK_COMPLETION = Counter(
    'task_completion_total',
    'Completed tasks',
    registry=REGISTRY,
    labelnames=['task_number', 'status']  # تغيير من labels إلى labelnames
)


MEMORY_USAGE = Gauge(
    'memory_usage_bytes',
    'Memory usage in bytes',
    labelnames=['type'],
    registry=REGISTRY,
)


# في بداية الملف بعد الاستيرادات
def validate_env_variables():
    """التحقق من وجود المتغيرات البيئية الضرورية"""
    logging.debug("🔍 Starting environment variables validation...")

    required_vars = [
        'SECRET_KEY',
        'APP_VERSION',
        'CORS_ORIGINS',
        'PORT',
        'LOG_LEVEL',
        'WORKERS',
        'REQUEST_TIMEOUT',  # إضافة جديدة
        'MAX_REQUEST_SIZE'  # إضافة جديدة
    ]
    redis_vars = ['REDIS_MERNA_URL', 'REDIS_AQRABENO_URL', 'REDIS_SWALF_URL', 'REDIS_MOSAAD_URL']

    missing_vars = []
    for var in required_vars:
        if not os.getenv(var):
            logging.debug(f"❌ Missing required variable: {var}")
            missing_vars.append(var)

    if not any(os.getenv(var) for var in redis_vars):
        logging.debug("❌ At least one Redis URL is required")
        missing_vars.append('At least one Redis URL is required')

    if missing_vars:
        raise EnvironmentError(f"Missing required environment variables: {', '.join(missing_vars)}")

    logging.debug("✅ All required environment variables are set.")

class AuthBackend(AuthenticationBackend):
    """خلفية المصادقة"""

    async def authenticate(self, request: Request) -> Tuple[AuthCredentials, BaseUser]:
        if "Authorization" not in request.headers:
            return AuthCredentials([]), UnauthenticatedUser()

        auth = request.headers["Authorization"]
        try:
            scheme, token = auth.split()
            if scheme.lower() != 'bearer':
                return AuthCredentials([]), UnauthenticatedUser()

            # التحقق من التوكن
            auth_manager = request.app.state.auth_manager
            payload = await auth_manager.validate_token(token)

            username = payload.get("sub")
            scopes = payload.get("scopes", [])

            return AuthCredentials(scopes), SimpleUser(username)
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            return AuthCredentials([]), UnauthenticatedUser()



# Constants and Configuration
API_VERSION = os.getenv('APP_VERSION', '1.0.0')
REDIS_MERNA_URL = os.getenv('REDIS_MERNA_URL')
REDIS_AQRABENO_URL = os.getenv('REDIS_AQRABENO_URL')
REDIS_SWALF_URL = os.getenv('REDIS_SWALF_URL')
REDIS_MOSAAD_URL = os.getenv('REDIS_MOSAAD_URL')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
CORS_ORIGINS = os.getenv('CORS_ORIGINS', '*').split(',')
PORT = int(os.getenv('PORT', 8000))
WORKERS = int(os.getenv('WORKERS', 4))
CACHE_TTL = int(os.getenv('CACHE_TTL', 3600))
SESSION_SECRET = token_urlsafe(32)
TEMP_DIR = Path(tempfile.gettempdir()) / "youtube_shorts_generator"
TEMP_DIR.mkdir(exist_ok=True)
# في قسم Constants and Configuration
REQUEST_TIMEOUT = float(os.getenv('REQUEST_TIMEOUT', '30'))
MAX_REQUEST_SIZE = int(os.getenv('MAX_REQUEST_SIZE', '10485760'))  # 10MB default

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,  # تغيير المستوى إلى DEBUG
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),  # إخراج السجلات إلى وحدة التحكم
    ]
)
logger = logging.getLogger(__name__)

# المتغير العام
worker_manager = None

# Initialize FastAPI app with configuration
app = FastAPI(
    title="YouTube Shorts Generator API",
    description="API for generating YouTube Shorts content using AI",
    version=API_VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Security configuration
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
security = HTTPBearer()

# Rate limiting
stream_rate_limit = RateLimiter(times=100, seconds=60)  # 100 requests per minute

# إضافة Middleware
app.add_middleware(LoggingMiddleware)

# إضافة معالج المهلة الزمنية
app.add_middleware(
    TimeoutMiddleware,
    timeout=float(os.getenv('REQUEST_TIMEOUT', '30'))  # 30 seconds default
)

# إضافة معالج الأخطاء
app.add_middleware(ErrorHandlingMiddleware)


app.add_middleware(WorkerMiddleware)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Range", "X-Total-Count", "X-Process-Time", "X-Request-ID"]
)

# Add session middleware
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    max_age=CACHE_TTL
)

app.add_middleware(
    AuthenticationMiddleware,
    backend=AuthBackend()
)

# Initialize metrics
ACTIVE_CONNECTIONS = Gauge(
    'active_connections',
    'Number of active connections',
    registry=REGISTRY,


)

# Base Models
class TokenData(BaseModel):
    """نموذج بيانات التوكن"""
    username: str
    scopes: List[str] = []
    exp: Optional[datetime] = None

    class Config:
        frozen = True


class User(BaseUser):
    """نموذج المستخدم الأساسي"""

    def __init__(self, username: str, scopes: List[str] = None):
        self.username = username
        self.scopes = scopes or []

    @property
    def is_authenticated(self) -> bool:
        return True

    @property
    def display_name(self) -> str:
        return self.username


class APIKeys(BaseModel):
    """نموذج مفاتيح API"""
    google_api_key: str = Field(..., description="Google API key")
    eleven_labs_api_key: str = Field(..., description="Eleven Labs API key")
    eleven_labs_voice_id: str = Field(..., description="Eleven Labs voice ID")

    @field_validator('google_api_key')
    def validate_google_key(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Google API key is required and must be valid')
        return v

    @field_validator('eleven_labs_api_key')
    def validate_eleven_labs_key(cls, v):
        if not v or len(v) < 10:
            raise ValueError('Eleven Labs API key is required and must be valid')
        return v

    @field_validator('eleven_labs_voice_id')
    def validate_voice_id(cls, v):
        if not v or len(v) < 5:
            raise ValueError('Voice ID is required and must be valid')
        return v

    class Config:
        extra = "forbid"
        schema_extra = {
            "example": {
                "google_api_key": "your_google_api_key_here",
                "eleven_labs_api_key": "your_eleven_labs_api_key_here",
                "eleven_labs_voice_id": "your_voice_id_here"
            }
        }

class AudioProcessingOptions(BaseModel):
    """نموذج خيارات معالجة الصوت"""
    max_duration: Optional[int] = Field(default=300, ge=10, le=600)
    format: Optional[str] = Field(default="mp3", pattern="^(mp3|wav)$")
    quality: Optional[str] = Field(default="high", pattern="^(low|medium|high)$")


class ProcessRequest(BaseModel):
    """نموذج طلب المعالجة"""
    topic: str = Field(..., min_length=1, max_length=500)
    api_keys: APIKeys
    timeout: Optional[int] = Field(default=300, ge=60, le=600)
    priority: Optional[str] = Field(default="normal", pattern="^(low|normal|high)$")
    audio_options: Optional[AudioProcessingOptions]

    class Config:
        schema_extra = {
            "example": {
                "topic": "Example topic",
                "api_keys": {
                    "google_api_key": "YOUR_GOOGLE_KEY",
                    "eleven_labs_api_key": "YOUR_ELEVEN_LABS_KEY",
                    "eleven_labs_voice_id": "YOUR_VOICE_ID"
                },
                "timeout": 300,
                "priority": "normal",
                "audio_options": {
                    "max_duration": 300,
                    "format": "mp3",
                    "quality": "high"
                }
            }
        }




class ErrorResponse(BaseModel):
    """نموذج استجابة الخطأ"""
    status: str = "error"
    message: str
    detail: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: Optional[str] = None


class HealthCheck(BaseModel):
    """نموذج فحص الصحة"""
    status: str
    version: str = API_VERSION
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    components: Dict[str, str] = {}


# Error Handlers
@app.exception_handler(CustomError)
async def custom_error_handler(request: Request, exc: CustomError) -> JSONResponse:
    """معالج الأخطاء المخصصة"""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            message=exc.message,
            detail=exc.detail,
            request_id=request.state.request_id if hasattr(request.state, 'request_id') else None
        ).model_dump()
    )


@app.exception_handler(ValidationError)
async def validation_error_handler(request: Request, exc: ValidationError) -> JSONResponse:
    """معالج أخطاء التحقق من الصحة"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=ErrorResponse(
            message="Validation error",
            detail=str(exc),
            request_id=request.state.request_id if hasattr(request.state, 'request_id') else None
        ).model_dump()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """معالج الأخطاء العام"""
    logger.error(f"Unhandled exception: {str(exc)}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            message="Internal server error",
            detail=str(exc) if app.debug else "An unexpected error occurred",
            request_id=request.state.request_id if hasattr(request.state, 'request_id') else None
        ).model_dump()
    )

@app.get("/metrics")
async def metrics():
    return Response(
        generate_latest(REGISTRY),
        media_type="text/plain"
    )


@app.get("/")
async def root():
    """نقطة النهاية الرئيسية"""
    workers_count = len(worker_manager.active_workers) if worker_manager else 0

    # فحص اتصالات Redis
    redis_ok = await check_redis_connection()

    # معلومات النظام
    system_info = {
        "memory_usage_mb": round(psutil.Process().memory_info().rss / 1024 / 1024, 2),
        "cpu_percent": psutil.cpu_percent(),
        "active_workers": workers_count
    }

    return JSONResponse({
        "status": "ok",
        "name": "YouTube Shorts Generator API",
        "version": API_VERSION,
        "environment": os.getenv('APP_ENV', 'production'),
        "health": {
            "status": "healthy" if redis_ok and workers_count > 0 else "degraded",
            "redis": "connected" if redis_ok else "error",
            "workers": workers_count
        },
        "endpoints": {
            "api": "/api",
            "docs": "/api/docs",
            "redoc": "/api/redoc",
            "health": "/health",
            "metrics": "/metrics"
        },
        "system": system_info,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.head("/")
async def head_root():
    """معالجة طلبات HEAD للمسار الجذر"""
    return Response(status_code=200)


# استجابة للأخطاء 404
@app.exception_handler(404)
async def custom_404_handler(request: Request, __):
    """معالج مخصص للمسارات غير الموجودة"""
    return JSONResponse(
        status_code=404,
        content={
            "status": "error",
            "message": "Route not found",
            "path": str(request.url),
            "available_endpoints": {
                "root": "/",
                "api": "/api",
                "docs": "/api/docs",
                "redoc": "/api/redoc",
                "health": "/health",
                "metrics": "/metrics"
            },
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )

@app.get("/api")
async def api_root():
    """نقطة نهاية API الرئيسية"""
    return JSONResponse({
        "name": "YouTube Shorts Generator API",
        "version": API_VERSION,
        "status": "active",
        "docs": {
            "swagger": "/api/docs",
            "redoc": "/api/redoc",
            "openapi": "/api/openapi.json"
        },
        "health_check": "/health",
        "metrics": "/metrics",
        "timestamp": datetime.now(timezone.utc).isoformat()
    })


@app.get('/favicon.ico')
async def favicon():
    """تقديم أيقونة الموقع"""
    favicon_path = os.path.join('static', 'favicon.ico')

    # إذا لم يوجد الملف، نقوم بإنشائه
    if not os.path.exists('static'):
        os.makedirs('static')

    if os.path.exists(favicon_path):
        return FileResponse(
            favicon_path,
            media_type="image/x-icon",
            headers={"Cache-Control": "public, max-age=31536000"}
        )
    return Response(status_code=204)  # إذا لم يوجد الملف، نرجع استجابة فارغة


# أضف مسار جديد للتحقق من الملفات الثابتة
@app.get('/static/{filepath:path}')
async def serve_static(filepath: str):
    """تقديم الملفات الثابتة"""
    static_path = os.path.join('static', filepath)
    if os.path.exists(static_path):
        return FileResponse(static_path)
    return Response(status_code=404)


@app.middleware("http")
async def check_redis_health(request: Request, call_next):
    """التحقق من صحة Redis قبل كل طلب"""
    try:
        if request.url.path != "/health":
            if not hasattr(app.state, 'redis_manager') or not app.state.redis_manager:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "status": "error",
                        "detail": "Redis manager not initialized",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )

            # اختبار اتصال واحد على الأقل
            redis_connected = False
            for service in app.state.redis_manager.instances.values():
                try:
                    await service['text'].ping()
                    redis_connected = True
                    break
                except:
                    continue

            if not redis_connected:
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "status": "error",
                        "detail": "Redis connection is not available",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )

        response = await call_next(request)
        return response
    except Exception as e:
        logging.error(f"❌ Middleware error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "error",
                "detail": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )




# Request ID Middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next) -> Response:
    """إضافة معرف للطلب"""
    request_id = request.headers.get('X-Request-ID', str(uuid.uuid4()))
    request.state.request_id = request_id

    response = await call_next(request)
    response.headers['X-Request-ID'] = request_id

    return response


# Process Time Middleware
@app.middleware("http")
async def add_process_time_header(request: Request, call_next) -> Response:
    """إضافة وقت المعالجة"""
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(process_time)

    # تحديث مقاييس الأداء
    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=request.url.path
    ).observe(process_time)


    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=str(response.status_code)
    ).inc()

    return response


# Error Logging Middleware
@app.middleware("http")
async def log_errors(request: Request, call_next) -> Response:
    """تسجيل الأخطاء"""
    try:
        return await call_next(request)
    except Exception as e:
        logger.error(
            f"Error processing request: {request.method} {request.url}\n"
            f"Error: {str(e)}\n"
            f"Traceback: {traceback.format_exc()}"
        )
        raise


# Authentication and Security Classes
class AuthConfig:
    """تكوينات المصادقة"""
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-here")
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))


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


class AuthManager:
    """مدير المصادقة والأمان"""
    def __init__(self, redis_manager: EnhancedRedisManager):
        if not redis_manager or not redis_manager.instances:
            raise ValueError("Valid Redis manager with active connections is required")
        self.redis = redis_manager.get_current_clients()['text']
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """التحقق من كلمة المرور"""
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """تشفير كلمة المرور"""
        return self.pwd_context.hash(password)

    async def get_user(self, username: str) -> Optional[UserInDB]:
        """استرجاع معلومات المستخدم"""
        try:
            user_data = await self.redis.client.hgetall(f"user:{username}")
            if not user_data:
                return None
            return UserInDB(
                username=username,
                hashed_password=user_data.get('hashed_password'),
                scopes=json.loads(user_data.get('scopes', '[]')),
                disabled=bool(int(user_data.get('disabled', '0')))
            )
        except Exception as e:
            logger.error(f"Error retrieving user data: {str(e)}")
            return None

    async def authenticate_user(self, username: str, password: str) -> Optional[UserInDB]:
        """مصادقة المستخدم"""
        user = await self.get_user(username)
        if not user:
            return None
        if not self.verify_password(password, user.hashed_password):
            return None
        if user.disabled:
            raise AuthenticationError("User account is disabled")
        return user

    async def create_tokens(self, user: UserInDB) -> Token:
        """إنشاء التوكن"""
        # إنشاء توكن الوصول
        access_token_expires = timedelta(minutes=AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = await self.create_access_token(
            data={"sub": user.username, "scopes": user.scopes},
            expires_delta=access_token_expires
        )

        # إنشاء توكن التحديث
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





# Auth Dependencies
async def get_current_user(
        security_scopes: SecurityScopes,
        token: str = Depends(oauth2_scheme),
        auth_manager: AuthManager = Depends(lambda: app.state.auth_manager)
) -> UserInDB:
    """استرجاع المستخدم الحالي"""
    if security_scopes.scopes:
        authenticate_value = f'Bearer scope="{security_scopes.scope_str}"'
    else:
        authenticate_value = "Bearer"

    try:
        # التحقق من التوكن
        payload = await auth_manager.validate_token(token)
        username = payload.get("sub")
        if not username:
            raise AuthenticationError("Could not validate credentials")

        # استرجاع المستخدم
        user = await auth_manager.get_user(username)
        if not user:
            raise AuthenticationError("User not found")

        # التحقق من الصلاحيات
        token_scopes = payload.get("scopes", [])
        for scope in security_scopes.scopes:
            if scope not in token_scopes:
                raise PermissionError(
                    detail=f"Not enough permissions. Required scope: {scope}"
                )

        return user

    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": authenticate_value}
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
            headers={"WWW-Authenticate": authenticate_value}
        )


# Auth Routes
@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_manager: AuthManager = Depends(lambda: app.state.auth_manager)
) -> Token:
    try:
        user = await auth_manager.authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return await auth_manager.create_tokens(user)
    except Exception as e:
        logging.error(f"خطأ في تسجيل الدخول: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during authentication"
        )


@app.post("/token/refresh", response_model=Token)
async def refresh_token(
        refresh_token: str = Body(..., embed=True),
        auth_manager: AuthManager = Depends(lambda: app.state.auth_manager)
) -> Token:
    """تحديث التوكن"""
    try:
        # التحقق من توكن التحديث
        payload = await auth_manager.validate_token(refresh_token, "refresh")
        username = payload.get("sub")
        if not username:
            raise AuthenticationError("Invalid refresh token")

        # استرجاع المستخدم
        user = await auth_manager.get_user(username)
        if not user:
            raise AuthenticationError("User not found")

        # إنشاء توكن جديد
        return await auth_manager.create_tokens(user)

    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )


# Initialize Auth Manager
@app.on_event("startup")
async def init_auth_manager():
    """تهيئة مدير المصادقة"""
    try:
        if not hasattr(app.state, 'redis_manager'):
            app.state.redis_manager = EnhancedRedisManager(
                max_retries=int(os.getenv('REDIS_MAX_RETRIES', 3)),
                timeout=int(os.getenv('REDIS_TIMEOUT', 30)),
                max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', 20))
            )
            await app.state.redis_manager.init_connections()

        app.state.auth_manager = AuthManager(app.state.redis_manager)
        logging.info("✅ Auth manager initialized successfully")
    except Exception as e:
        logging.error(f"❌ Failed to initialize auth manager: {str(e)}")
        # عدم رفع الخطأ هنا للسماح للتطبيق بالاستمرار
        app.state.auth_manager = None



# Request Tracking
class RequestTracker:
    """تتبع الطلبات"""
    def __init__(self, process_id: str, user_id: str, request_data: Dict):
        self.process_id = process_id
        self.user_id = user_id
        self.request_data = request_data
        self.start_time = datetime.now(timezone.utc)
        self.status = "pending"
        self.error = None

    async def start(self):
        """تسجيل بداية المعالجة"""
        self.status = "processing"
        logger.info(f"Starting process {self.process_id} for user {self.user_id}")

    async def complete(self, result: Dict):
        """تسجيل اكتمال المعالجة"""
        self.status = "completed"
        duration = (datetime.now(timezone.utc) - self.start_time).total_seconds()
        logger.info(f"Process {self.process_id} completed in {duration:.2f} seconds")
        return {
            "process_id": self.process_id,
            "status": self.status,
            "duration": duration,
            "result": result
        }

    async def fail(self, error: str):
        """تسجيل فشل المعالجة"""
        self.status = "failed"
        self.error = error
        logger.error(f"Process {self.process_id} failed: {error}")
        return {
            "process_id": self.process_id,
            "status": self.status,
            "error": error
        }

# Processing Functions
async def process_content(
        core_logic: AsyncStreamingCoreLogic,
        process_id: str,
        topic: str,
        timeout: int,
        priority: str,
        audio_options: Optional[AudioProcessingOptions],
        request_tracker: RequestTracker
) -> None:
    """معالجة المحتوى"""
    try:
        # بدء المعالجة
        await request_tracker.start()

        # بدء سلسلة المهام
        await core_logic.chain_tasks(topic)

        # تسجيل النجاح
        await request_tracker.complete({
            "status": "success",
            "message": "Content processing completed successfully"
        })

    except Exception as e:
        logger.error(f"Content processing error: {str(e)}")
        await request_tracker.fail(str(e))

# API Endpoints
@app.post("/api/process", status_code=status.HTTP_202_ACCEPTED)
async def process_request(
    request: ProcessRequest,
    background_tasks: BackgroundTasks,
    current_user: UserInDB = Depends(get_current_user),
    request_id: str = Header(None)
) -> JSONResponse:
    """معالجة طلب إنشاء المحتوى"""
    try:
        # التحقق من الصلاحيات
        if "process" not in current_user.scopes:
            raise PermissionError("Insufficient permissions")

        # التحقق من توفر الخدمة
        if not app.state.core_logic or not app.state.core_logic.redis:
            raise ServiceConfigError("Service not properly initialized")

        # إنشاء معرف للطلب
        process_id = request_id or str(uuid.uuid4())

        # تتبع الطلب
        request_tracker = RequestTracker(
            process_id=process_id,
            user_id=current_user.username,
            request_data=request.model_dump()
        )

        try:
            # التحقق من مفاتيح API
            await app.state.core_logic.validate_api_keys(
                request.api_keys.google_api_key,
                request.api_keys.eleven_labs_api_key,
                request.api_keys.eleven_labs_voice_id
            )

            # تهيئة APIs
            await app.state.core_logic.configure_apis(
                request.api_keys.google_api_key,
                request.api_keys.eleven_labs_api_key,
                request.api_keys.eleven_labs_voice_id
            )

            # إضافة مهمة المعالجة
            background_tasks.add_task(
                process_content,
                app.state.core_logic,
                process_id,
                request.topic,
                request.timeout,
                request.priority,
                request.audio_options,
                request_tracker
            )

            return JSONResponse(
                status_code=status.HTTP_202_ACCEPTED,
                content={
                    "status": "processing",
                    "message": "Task chain started successfully",
                    "process_id": process_id,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

        except Exception as e:
            await request_tracker.fail(str(e))
            raise

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Process request error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.get("/api/audio/{process_id}")
async def get_audio(
        process_id: str,
        current_user: UserInDB = Depends(get_current_user)
) -> JSONResponse:
    """الحصول على الصوت"""
    try:
        # التحقق من توفر الخدمة
        if not app.state.core_logic:
            raise ServiceConfigError("Service not properly initialized")

        # استرداد معلومات الصوت
        task_status = await app.state.core_logic.get_task_status(8)

        if not task_status or task_status.get('status') != 'completed':
            raise ResourceNotFoundError("Audio not ready")

        # الحصول على معلومات الصوت
        audio_info = task_status['result']['content']
        eleven_labs_voice_id = app.state.core_logic.eleven_labs_config.get('voice_id')

        if not eleven_labs_voice_id:
            raise APIConfigurationError("Voice ID not configured")

        return JSONResponse({
            "status": "success",
            "audio_metadata": audio_info,
            "external_audio_url": f"https://api.elevenlabs.io/v1/text-to-speech/{eleven_labs_voice_id}",
            "audio_id": task_status['result'].get('external_audio_id')
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting audio: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# تعديل على نقطة النهاية stream_updates
@app.get("/api/stream/{process_id}")
async def stream_updates(
        process_id: str,
        current_user: UserInDB = Depends(get_current_user),
        _: Any = Depends(stream_rate_limit)
) -> StreamingResponse:
    """بث تحديثات المعالجة"""
    try:
        async def event_generator():
            """مولد الأحداث"""
            try:
                last_event_id = None
                while True:
                    try:
                        async with asyncio.timeout(10):
                            updates = await app.state.core_logic.get_process_updates(
                                process_id,
                                last_event_id
                            )

                            if updates:
                                for update in updates:
                                    # معالجة خاصة للمهمة 8
                                    if update.get('task_number') == 8:
                                        update = await handle_audio_update(update)

                                    last_event_id = update.get('id')
                                    yield f"id: {last_event_id}\ndata: {json.dumps(update)}\n\n"

                            else:
                                # إرسال نبض القلب
                                yield f"event: heartbeat\ndata: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"

                    except asyncio.TimeoutError:
                        yield f"event: heartbeat\ndata: {json.dumps({'timestamp': datetime.now(timezone.utc).isoformat()})}\n\n"
                        continue

            except Exception as e:
                logging.error(f"Stream error: {str(e)}")
                yield f"event: error\ndata: {json.dumps({'error': str(e)})}\n\n"
                raise

        return StreamingResponse(
            event_generator(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Transfer-Encoding": "chunked"
            }
        )

    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Error setting up stream: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# إضافة دالة handle_audio_update
async def handle_audio_update(update: Dict) -> Dict:
    """
    معالجة تحديثات الصوت بشكل آمن

    Args:
        update (Dict): تحديث المهمة الصوتية

    Returns:
        Dict: التحديث المعالج
    """
    try:
        # التحقق من صحة التحديث
        if not isinstance(update, dict):
            logging.warning("Invalid audio update: not a dictionary")
            return update

        # معالجة بيانات الصوت
        if 'audio_data' in update:
            # إزالة البيانات الكبيرة لتجنب استهلاك الذاكرة
            logging.info("Removing large audio data from update")
            update['audio_data'] = None

        # التحقق من وجود المفاتيح الأساسية
        required_keys = ['task_number', 'status']
        for key in required_keys:
            if key not in update:
                logging.warning(f"Missing key in audio update: {key}")

        # إضافة معلومات إضافية
        update['processed_at'] = datetime.now(timezone.utc).isoformat()
        update['processing_host'] = socket.gethostname()

        return update

    except Exception as e:
        logging.error(f"Error processing audio update: {str(e)}")
        return {
            'status': 'error',
            'message': f'Failed to process audio update: {str(e)}',
            'original_update': update
        }


async def check_redis_connection() -> bool:
    try:
        if not hasattr(app.state, 'redis_manager'):
            logging.error("Redis manager not initialized")
            return False

        current_clients = await app.state.redis_manager.get_current_clients()
        await current_clients['text'].ping()
        logging.info("✅ Redis connection is healthy")
        return True

    except Exception as e:
        logging.error(f"❌ Redis connection check failed: {str(e)}")
        return False

# Health Check Endpoint
# نقطة نهاية فحص الصحة
@app.get("/health")
async def health_check():
    """فحص صحة API"""
    try:
        # فحص Redis
        redis_ok = await check_redis_connection()

        # فحص المكونات
        components_status = {
            "redis": "ok" if redis_ok else "error",
            "auth": "ok" if hasattr(app.state, 'auth_manager') else "error",
            "worker_manager": "ok" if worker_manager else "error"
        }

        # معلومات النظام
        system_info = {
            "memory_usage_mb": psutil.Process().memory_info().rss / 1024 / 1024,
            "cpu_percent": psutil.cpu_percent(),
            "workers": len(worker_manager.active_workers) if worker_manager else 0
        }

        # الحالة الإجمالية
        overall_status = "healthy" if all(v == "ok" for v in components_status.values()) else "degraded"

        return JSONResponse({
            "status": overall_status,
            "version": API_VERSION,
            "components": components_status,
            "system": system_info,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logging.error(f"❌ Health check error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


@app.get("/health/redis")
async def check_redis_connections():
    """فحص اتصالات Redis"""
    try:
        status = {}
        for service in RedisServiceName:
            try:
                await app.state.redis_manager.switch_service(service)
                status[service.value] = "connected"
            except Exception as e:
                status[service.value] = f"error: {str(e)}"

        return JSONResponse({
            "status": "healthy" if all(s == "connected" for s in status.values()) else "degraded",
            "services": status,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
        )


# معالج الأخطاء العام
@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """معالج الأخطاء العام"""
    error_msg = str(exc)
    error_type = type(exc).__name__

    # معالجة خاصة لأخطاء Redis
    if isinstance(exc, AttributeError) and "redis_manager" in error_msg:
        error_msg = "Failed to initialize Redis connection. Please check Redis configuration."

    logging.error(f"❌ Error: {error_type} - {error_msg}\n{traceback.format_exc()}")

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "status": "error",
            "error_type": error_type,
            "detail": error_msg,
            "path": str(request.url),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )


# معالج أخطاء التحقق
@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError):
    """معالج أخطاء التحقق من الصحة"""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "status": "error",
            "error_type": "ValidationError",
            "detail": exc.errors(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    )



# Application Lifecycle Management
class AppLifecycle:
    """إدارة دورة حياة التطبيق"""

    def __init__(self):
        self.scheduler = AsyncIOScheduler()
        self.cleanup_interval = int(os.getenv('CLEANUP_INTERVAL', 3600))  # ساعة واحدة
        self.monitoring_interval = int(os.getenv('MONITORING_INTERVAL', 60))  # دقيقة واحدة

    async def startup(self):
        """تهيئة التطبيق عند البدء"""
        try:
            # إنشاء مدير Redis أولاً
            app.state.redis_manager = EnhancedRedisManager(
                max_retries=int(os.getenv('REDIS_MAX_RETRIES', 3)),
                timeout=int(os.getenv('REDIS_TIMEOUT', 30)),
                max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', 20))
            )

            # تهيئة Redis
            await app.state.redis_manager.init_connections()

            # تهيئة المكونات الأخرى...
            app.state.core_logic = AsyncStreamingCoreLogic(
                redis_manager=app.state.redis_manager,
                max_retries=int(os.getenv('MAX_RETRIES', 3)),
                timeout=int(os.getenv('TIMEOUT', 30))
            )
            await app.state.core_logic.init_redis()

            # تهيئة مدير المصادقة
            app.state.auth_manager = AuthManager(app.state.redis_manager)

            # بدء المجدول
            self.scheduler.start()

            logging.info("✅ Application started successfully")

        except Exception as e:
            logging.error(f"❌ Startup error: {str(e)}")
            raise

    async def shutdown(self):
        """تنظيف الموارد عند الإيقاف"""
        try:
            # إيقاف المجدول
            self.scheduler.shutdown()

            # تنظيف Redis
            if hasattr(app.state, 'redis_manager'):
                await app.state.redis_manager.cleanup()

            # تنظيف Core Logic
            if hasattr(app.state, 'core_logic'):
                await app.state.core_logic.cleanup_all_tasks()

            # تنظيف الملفات المؤقتة
            await self._cleanup_temp_files()

            logger.info("Application shutdown completed successfully")

        except Exception as e:
            logger.error(f"Shutdown error: {str(e)}")
            raise

    def _schedule_tasks(self):
        """جدولة المهام الدورية"""
        # تنظيف دوري
        self.scheduler.add_job(
            self._periodic_cleanup,
            trigger=IntervalTrigger(seconds=self.cleanup_interval),
            id='cleanup_job',
            name='Periodic Cleanup',
            replace_existing=True
        )

        # مراقبة الموارد
        self.scheduler.add_job(
            self._monitor_resources,
            trigger=IntervalTrigger(seconds=self.monitoring_interval),
            id='monitoring_job',
            name='Resource Monitoring',
            replace_existing=True
        )

        # تنظيف الجلسات القديمة في منتصف الليل
        self.scheduler.add_job(
            self._cleanup_old_sessions,
            trigger=CronTrigger(hour=0, minute=0),
            id='session_cleanup_job',
            name='Session Cleanup',
            replace_existing=True
        )

    async def _periodic_cleanup(self):
        """تنظيف دوري للموارد"""
        try:
            # تنظيف البيانات المؤقتة في Redis
            await app.state.redis_manager.cleanup_old_data()

            # تنظيف الملفات المؤقتة
            await self._cleanup_temp_files()

            # تنظيف البيانات القديمة في Core Logic
            await app.state.core_logic.cleanup_old_data()

            logger.info("Periodic cleanup completed successfully")

        except Exception as e:
            logger.error(f"Periodic cleanup error: {str(e)}")

    async def _monitor_resources(self):
        """مراقبة استخدام الموارد"""
        try:
            # مراقبة الذاكرة
            memory_info = psutil.Process().memory_info()
            MEMORY_USAGE.labels(type='rss').set(memory_info.rss)
            MEMORY_USAGE.labels(type='vms').set(memory_info.vms)

            # مراقبة CPU
            cpu_percent = psutil.cpu_percent()
            RESOURCE_USAGE.labels(resource_type='cpu').set(cpu_percent)

            # مراقبة القرص
            disk_usage = psutil.disk_usage('/')
            RESOURCE_USAGE.labels(resource_type='disk').set(disk_usage.percent)

            logger.debug("Resource monitoring completed")

        except Exception as e:
            logger.error(f"Resource monitoring error: {str(e)}")

    async def _cleanup_old_sessions(self):
        """تنظيف الجلسات القديمة"""
        try:
            # تنظيف الجلسات القديمة من Redis
            session_keys = await app.state.redis_manager.keys('session:*')
            for key in session_keys:
                try:
                    session_data = await app.state.redis_manager.get(key)
                    if session_data:
                        data = json.loads(session_data)
                        last_activity = datetime.fromisoformat(data.get('last_activity', ''))
                        if (datetime.now(timezone.utc) - last_activity).total_seconds() > CACHE_TTL:
                            await app.state.redis_manager.delete(key)
                except Exception as e:
                    logger.error(f"Error cleaning session {key}: {str(e)}")

            logger.info("Old sessions cleanup completed")

        except Exception as e:
            logger.error(f"Sessions cleanup error: {str(e)}")

    async def _cleanup_temp_files(self):
        """تنظيف الملفات المؤقتة"""
        try:
            # تنظيف الملفات القديمة
            current_time = datetime.now(timezone.utc)
            for file_path in TEMP_DIR.glob('*'):
                if file_path.is_file():
                    file_age = current_time - datetime.fromtimestamp(
                        file_path.stat().st_mtime,
                        timezone.utc
                    )
                    if file_age.total_seconds() > CACHE_TTL:
                        file_path.unlink()
                        logger.debug(f"Removed old temp file: {file_path}")

            logger.debug("Temp files cleanup completed")

        except Exception as e:
            logger.error(f"Temp files cleanup error: {str(e)}")


# Application Lifecycle Events
app_lifecycle = AppLifecycle()

# app.py

# إضافة الاستيراد
from auth_manager import AuthManager


@app.on_event("startup")
async def startup_event():
    """تهيئة التطبيق عند بدء التشغيل"""
    try:
        global worker_manager
        validate_env_variables()

        # تهيئة مدير العمليات
        worker_manager = WorkerManager(max_workers=WORKERS)
        await worker_manager.init_workers()

        # التأكد من عدم تهيئة Redis Manager عدة مرات
        if not hasattr(app.state, "redis_manager"):
            logging.info("🔍 Initializing Redis Manager...")
            app.state.redis_manager = EnhancedRedisManager(
                max_retries=int(os.getenv('REDIS_MAX_RETRIES', 3)),
                timeout=int(os.getenv('REDIS_TIMEOUT', 30)),
                max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', 20))
            )
            await app.state.redis_manager.init_connections()

        # إضافة المسارات
        app.include_router(api_router, prefix="/api")

        logging.info("✅ Application started successfully")

    except Exception as e:
        logging.critical(f"❌ Application startup failed: {e}", exc_info=True)
        raise

@app.on_event("shutdown")
async def shutdown_event():
    """إجراءات إيقاف التشغيل وتنظيف الموارد"""
    try:
        global worker_manager
        logging.info("Starting application shutdown...")

        if worker_manager:
            # إيقاف العمليات بشكل آمن
            await worker_manager.graceful_shutdown()

        # تنظيف مقاييس Prometheus
        if os.getenv('PROMETHEUS_MULTIPROC_DIR'):
            multiprocess.mark_process_dead(os.getpid())

        # إيقاف المهام المعلقة بشكل آمن
        tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
        for task in tasks:
            task.cancel()
            try:
                await asyncio.wait_for(task, timeout=15.0)
            except asyncio.TimeoutError:
                logging.warning(f"Task {task.get_name()} timed out during shutdown")
            except Exception as e:
                logging.warning(f"Error cancelling task: {str(e)}")

        # تنظيف الموارد
        await cleanup_resources()

        logging.info("✅ Application shutdown completed successfully")

    except Exception as e:
        logging.error(f"❌ Error during shutdown: {str(e)}")
    finally:
        # تأكد من تحرير جميع الموارد
        if hasattr(app.state, 'redis_manager'):
            try:
                await app.state.redis_manager.cleanup()
            except Exception as e:
                logging.error(f"Error cleaning up Redis manager: {str(e)}")
            delattr(app.state, 'redis_manager')

async def cleanup_resources():
    """تنظيف الموارد"""
    try:
        # تنظيف core logic أولاً إذا كان موجوداً
        if hasattr(app.state, 'core_logic'):
            logging.info("Cleaning up core logic...")
            if hasattr(app.state.core_logic, 'redis'):
                app.state.core_logic.redis = None
            delattr(app.state, 'core_logic')

        # تنظيف redis_manager
        if hasattr(app.state, 'redis_manager'):
            logging.info("Cleaning up Redis manager...")
            try:
                await app.state.redis_manager.cleanup()
            except Exception as e:
                logging.error(f"Error cleaning up Redis manager: {str(e)}")
            finally:
                delattr(app.state, 'redis_manager')

        # تنظيف auth_manager
        if hasattr(app.state, 'auth_manager'):
            logging.info("Cleaning up auth manager...")
            delattr(app.state, 'auth_manager')

        logging.info("✅ Resources cleaned up successfully")

    except Exception as e:
        logging.error(f"Error in cleanup_resources: {str(e)}")

# Main Entry Point
if __name__ == "__main__":
    import uvicorn
    import multiprocessing

    # تحديد عدد العمال
    workers = int(os.getenv('WORKERS', multiprocessing.cpu_count() * 2 + 1))

    # تكوين التشغيل
    config = uvicorn.Config(
        "app:app",
        host=os.getenv('HOST', '0.0.0.0'),
        port=int(os.getenv('PORT', 8000)),
        workers=workers,
        reload=os.getenv('APP_ENV') == 'development',
        log_level=os.getenv('LOG_LEVEL', 'info').lower(),
        loop="auto",
        proxy_headers=True,
        forwarded_allow_ips="*",
        timeout_keep_alive=int(os.getenv('KEEPALIVE_TIMEOUT', 65)),
        access_log=True
    )

    # توليد ملف المتغيرات البيئية إذا لم يكن موجوداً
    if not Path('.env').exists():
        with open('.env', 'w') as f:
            f.write('''# Application Settings
APP_ENV=development
APP_VERSION=1.0.0
LOG_LEVEL=INFO
DEBUG=1

# Server Settings
HOST=0.0.0.0
PORT=8000
WORKERS=4
KEEPALIVE_TIMEOUT=65

# Redis Settings
REDIS_MAX_RETRIES=3
REDIS_TIMEOUT=30
REDIS_MAX_CONNECTIONS=20

# Security Settings
SECRET_KEY=your-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
SESSION_SECRET=your-session-secret-here

# CORS Settings
CORS_ORIGINS=*

# Cache Settings
CACHE_TTL=3600

# Cleanup Settings
CLEANUP_INTERVAL=3600
MONITORING_INTERVAL=60

# API Settings
MAX_RETRIES=3
TIMEOUT=30
''')

    # تشغيل الخادم
    server = uvicorn.Server(config)
    server.run()
