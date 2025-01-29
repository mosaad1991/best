import pytest
from fastapi.testclient import TestClient
from app import app
import os
from dotenv import load_dotenv

# تحميل المتغيرات البيئية
load_dotenv()

client = TestClient(app)


def test_process_request():
    """اختبار معالجة الطلب"""
    # احصل على توكن صالح أولاً
    token_response = client.post(
        "/token",
        data={
            "username": "testuser",  # استبدل بمستخدم صالح
            "password": "testpassword"  # استبدل بكلمة مرور صالحة
        }
    )
    access_token = token_response.json()['access_token']

    # إرسال طلب المعالجة
    response = client.post(
        "/api/process",
        headers={"Authorization": f"Bearer {access_token}"},
        json={
            "topic": "قصة تاريخية",
            "api_keys": {
                "google_api_key": os.getenv('GOOGLE_API_KEY'),
                "eleven_labs_api_key": os.getenv('ELEVEN_LABS_API_KEY'),
                "eleven_labs_voice_id": os.getenv('ELEVEN_LABS_VOICE_ID')
            }
        }
    )

    assert response.status_code == 202
    assert "process_id" in response.json()