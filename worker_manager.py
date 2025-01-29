import asyncio
import logging
import multiprocessing
import os
from typing import List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class WorkerManager:
    """مدير العمليات"""

    def __init__(self, max_workers: Optional[int] = None):
        """تهيئة مدير العمليات"""
        self.max_workers = max_workers or multiprocessing.cpu_count() * 2 + 1
        self.active_workers: List[int] = []
        self.shutdown_timeout = 30  # ثانية
        self._cleanup_tasks = []
        self._is_shutting_down = False

    async def init_workers(self) -> None:
        """تهيئة العمليات"""
        try:
            for _ in range(self.max_workers):
                # إنشاء عملية جديدة
                process_id = os.getpid()
                self.active_workers.append(process_id)
                logger.info(f"Worker {process_id} initialized")

        except Exception as e:
            logger.error(f"Error initializing workers: {str(e)}")
            raise

    async def graceful_shutdown(self) -> None:
        """إغلاق آمن للعمليات"""
        if self._is_shutting_down:
            return

        self._is_shutting_down = True
        logger.info("Starting graceful shutdown...")

        try:
            # إيقاف العمليات الجديدة
            remaining_workers = self.active_workers.copy()
            shutdown_start = datetime.now(timezone.utc)

            while remaining_workers and (datetime.now(timezone.utc) - shutdown_start).total_seconds() < self.shutdown_timeout:
                for worker_id in remaining_workers[:]:
                    try:
                        # إرسال إشارة الإيقاف
                        os.kill(worker_id, 15)  # SIGTERM
                        remaining_workers.remove(worker_id)
                        logger.info(f"Worker {worker_id} shutdown signal sent")
                    except ProcessLookupError:
                        remaining_workers.remove(worker_id)
                    except Exception as e:
                        logger.error(f"Error shutting down worker {worker_id}: {str(e)}")

                if remaining_workers:
                    await asyncio.sleep(1)

            # التعامل مع العمليات المتبقية
            for worker_id in remaining_workers:
                try:
                    os.kill(worker_id, 9)  # SIGKILL
                    logger.warning(f"Force killed worker {worker_id}")
                except:
                    pass

        except Exception as e:
            logger.error(f"Error during graceful shutdown: {str(e)}")
        finally:
            self._is_shutting_down = False
            self.active_workers.clear()
            logger.info("Graceful shutdown completed")

    async def cleanup(self) -> None:
        """تنظيف الموارد"""
        try:
            # تنظيف المهام المعلقة
            for task in self._cleanup_tasks:
                if not task.done():
                    task.cancel()
            self._cleanup_tasks.clear()

            # إغلاق العمليات
            await self.graceful_shutdown()

        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
            raise

    def add_cleanup_task(self, task: asyncio.Task) -> None:
        """إضافة مهمة تنظيف"""
        self._cleanup_tasks.append(task)

    @property
    def worker_count(self) -> int:
        """عدد العمليات النشطة"""
        return len(self.active_workers)