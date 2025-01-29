from typing import Optional

class AuthenticationError(Exception):
    """خطأ في المصادقة"""
    def __init__(self, message: str = "Authentication failed", detail: Optional[str] = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)

class ValidationError(Exception):
    """خطأ في التحقق من الصحة"""
    def __init__(self, message: str = "Validation error", detail: Optional[str] = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)

class PermissionError(Exception):
    """خطأ في الصلاحيات"""
    def __init__(self, message: str = "Insufficient permissions", detail: Optional[str] = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)

class ResourceNotFoundError(Exception):
    """خطأ عدم وجود المورد"""
    def __init__(self, message: str = "Resource not found", detail: Optional[str] = None):
        self.message = message
        self.detail = detail
        super().__init__(self.message)