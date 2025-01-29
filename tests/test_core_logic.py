import pytest
import asyncio
from core_logic import AsyncStreamingCoreLogic
import os
from dotenv import load_dotenv

# تحميل المتغيرات البيئية
load_dotenv()


@pytest.mark.asyncio
async def test_init_redis():
    """اختبار تهيئة Redis"""
    core_logic = AsyncStreamingCoreLogic(
        redis_url=os.getenv('REDIS_URL', 'redis://localhost:6379')
    )
    assert await core_logic.init_redis() is True


@pytest.mark.asyncio
async def test_validate_api_keys():
    """اختبار التحقق من صحة مفاتيح API"""
    core_logic = AsyncStreamingCoreLogic(
        redis_url=os.getenv('REDIS_URL', 'redis://localhost:6379')
    )

    # استبدل بمفاتيح صالحة من متغيراتك البيئية
    valid_result = await core_logic.validate_api_keys(
        google_api_key=os.getenv('GOOGLE_API_KEY'),
        eleven_labs_api_key=os.getenv('ELEVEN_LABS_API_KEY'),
        eleven_labs_voice_id=os.getenv('ELEVEN_LABS_VOICE_ID')
    )
    assert valid_result is True


@pytest.mark.asyncio
async def test_task_generation():
    """اختبار توليد المهام"""
    core_logic = AsyncStreamingCoreLogic(
        redis_url=os.getenv('REDIS_URL', 'redis://localhost:6379')
    )

    await core_logic.init_redis()

    # اختبار توليد المواضيع
    result = await core_logic.task_1_generate_youtube_shorts_topics("تاريخ الإسلام")

    assert result['status'] == 'success'
    assert 'content' in result
    assert len(result['content']) > 0





