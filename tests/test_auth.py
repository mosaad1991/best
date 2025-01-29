import pytest
from fastapi.testclient import TestClient
from app import app
import os
from dotenv import load_dotenv

# تحميل المتغيرات البيئية
load_dotenv()

client = TestClient(app)

def test_token_generation():
    """اختبار توليد التوكن"""
    response = client.post(
        "/token",
        data={
            "username": "testuser",  # استبدل بمستخدم صالح
            "password": "testpassword"  # استبدل بكلمة مرور صالحة
        }
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert "refresh_token" in response.json()

def test_unauthorized_access():
    """اختبار رفض الوصول بدون مصادقة"""
    response = client.post(
        "/api/process",
        json={"topic": "اختبار"}
    )
    assert response.status_code == 401