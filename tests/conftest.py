import pytest
import asyncio

# تكوين pytest للعمل مع الدوال الغير متزامنة
@pytest.fixture(scope="session")
def event_loop():
    """إنشاء حلقة حدث للاختبارات"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()