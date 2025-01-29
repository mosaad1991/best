from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
import time
import logging
import traceback
from datetime import datetime, timezone
import asyncio
from typing import Optional
from prometheus_client import Counter, Histogram, multiprocess

# مقاييس الأداء
REQUEST_DURATION = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration in seconds',
    ['method', 'endpoint', 'status']
)

ERROR_COUNTER = Counter(
    'http_request_errors_total',
    'Total HTTP request errors',
    ['method', 'endpoint', 'error_type']
)

class WorkerMiddleware(BaseHTTPMiddleware):
    """معالج الطلبات والأخطاء الأساسي"""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get('X-Request-ID', None)
        start_time = time.time()
        response = None
        error_logged = False

        try:
            # تسجيل بداية الطلب
            logging.info(
                f"Processing request: {request.method} {request.url.path} "
                f"[ID: {request_id}]"
            )

            # تعيين المهلة الزمنية للطلب
            timeout = 30  # 30 ثانية كحد أقصى
            try:
                async with asyncio.timeout(timeout):
                    response = await call_next(request)
            except asyncio.TimeoutError:
                error_logged = True
                logging.error(
                    f"Request timeout after {timeout}s: "
                    f"{request.method} {request.url.path}"
                )
                return JSONResponse(
                    status_code=504,
                    content={
                        "detail": "Request timeout",
                        "status": "error",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )

            # قياس وقت المعالجة
            process_time = time.time() - start_time
            
            # تحديث المقاييس
            REQUEST_DURATION.labels(
                method=request.method,
                endpoint=request.url.path,
                status=response.status_code
            ).observe(process_time)

            # إضافة معلومات المعالجة للاستجابة
            response.headers["X-Process-Time"] = str(process_time)
            if request_id:
                response.headers["X-Request-ID"] = request_id

            # تسجيل نجاح الطلب
            logging.info(
                f"Request completed: {request.method} {request.url.path} "
                f"[{response.status_code}] in {process_time:.3f}s"
            )

            return response

        except Exception as e:
            if not error_logged:
                # تسجيل الخطأ
                logging.error(
                    f"Request failed: {request.method} {request.url.path}\n"
                    f"Error: {str(e)}\n{traceback.format_exc()}"
                )

                # تحديث عداد الأخطاء
                ERROR_COUNTER.labels(
                    method=request.method,
                    endpoint=request.url.path,
                    error_type=type(e).__name__
                ).inc()

            process_time = time.time() - start_time
            return JSONResponse(
                status_code=500,
                content={
                    "detail": "Internal server error",
                    "status": "error",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "request_id": request_id,
                    "process_time": process_time
                }
            )

class TimeoutMiddleware(BaseHTTPMiddleware):
    """معالج المهلة الزمنية للطلبات"""

    def __init__(self, app, timeout: float = 30):
        super().__init__(app)
        self.timeout = timeout

    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            async with asyncio.timeout(self.timeout):
                return await call_next(request)
        except asyncio.TimeoutError:
            return JSONResponse(
                status_code=504,
                content={
                    "detail": f"Request timeout after {self.timeout}s",
                    "status": "error",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )

class LoggingMiddleware(BaseHTTPMiddleware):
    """معالج تسجيل الطلبات"""

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.time()
        response = None

        try:
            # تسجيل بداية الطلب
            logging.info(f"-> {request.method} {request.url.path}")
            
            response = await call_next(request)
            
            # تسجيل نهاية الطلب
            process_time = time.time() - start_time
            logging.info(
                f"<- {request.method} {request.url.path} "
                f"[{response.status_code}] {process_time:.3f}s"
            )
            
            return response

        except Exception as e:
            logging.error(
                f"! {request.method} {request.url.path}\n"
                f"Error: {str(e)}\n{traceback.format_exc()}"
            )
            raise

class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    """معالج الأخطاء المتقدم"""

    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            response = await call_next(request)
            return response

        except Exception as e:
            error_id = f"ERR-{int(time.time())}"
            logging.error(
                f"Error ID: {error_id}\n"
                f"Request: {request.method} {request.url.path}\n"
                f"Error: {str(e)}\n{traceback.format_exc()}"
            )

            return JSONResponse(
                status_code=500,
                content={
                    "error_id": error_id,
                    "detail": "An unexpected error occurred",
                    "status": "error",
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            )