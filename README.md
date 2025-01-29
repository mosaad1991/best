# YouTube Shorts Generator API

خدمة API لتوليد محتوى YouTube Shorts باستخدام الذكاء الاصطناعي

## 🚀 المميزات

- توليد نصوص ومواضيع ذكية
- تحويل النص إلى صوت باستخدام ElevenLabs
- تحليل الاتجاهات وتحسين SEO
- معالجة متعددة المراحل للمحتوى
- دعم التدفق المباشر للتحديثات
- مراقبة وتتبع الأداء
- نظام مصادقة متقدم

## 📋 المتطلبات

- Python 3.11 أو أحدث
- Redis
- FFmpeg (لمعالجة الصوت)
- تكوين بيئة التشغيل
- مفاتيح API للخدمات المستخدمة

## ⚙️ الإعداد

1. استنساخ المستودع:
```bash
git clone https://github.com/yourusername/youtube-shorts-generator.git
cd youtube-shorts-generator
```

2. إنشاء وتفعيل البيئة الافتراضية:
```bash
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# أو
.venv\Scripts\activate  # Windows
```

3. تثبيت المتطلبات:
```bash
pip install -r requirements.txt
```

4. إعداد ملف `.env`:
```bash
cp .env.example .env
# قم بتعديل الإعدادات حسب احتياجاتك
```

5. تشغيل التطبيق:
```bash
python -m gunicorn app:app
```

## 🔧 التكوين

### المتغيرات البيئية الأساسية

```ini
# تكوين التطبيق
APP_ENV=production
APP_VERSION=1.0.0
PORT=10000
LOG_LEVEL=INFO

# إعدادات Redis
REDIS_MAX_RETRIES=3
REDIS_TIMEOUT=30
REDIS_MAX_CONNECTIONS=20

# إعدادات الأمان
SECRET_KEY=your-secret-key
SESSION_SECRET=your-session-secret

# إعدادات CORS
CORS_ORIGINS=*
```

### تكوين Gunicorn

تم تكوين Gunicorn لأداء مثالي مع:
- إدارة العمليات المتعددة
- التعامل الآمن مع الإغلاق
- مراقبة الموارد
- تسجيل متقدم

## 📚 واجهات API

### المصادقة

```http
POST /token
Content-Type: application/x-www-form-urlencoded

username=user&password=pass
```

### معالجة المحتوى

```http
POST /api/process
Content-Type: application/json
Authorization: Bearer <token>

{
    "topic": "موضوع الفيديو",
    "api_keys": {
        "google_api_key": "your_key",
        "eleven_labs_api_key": "your_key",
        "eleven_labs_voice_id": "voice_id"
    }
}
```

### تدفق التحديثات

```http
GET /api/stream/{process_id}
Authorization: Bearer <token>
```

## 🔍 المراقبة

- فحص صحة النظام: `/health`
- فحص Redis: `/health/redis`
- مقاييس Prometheus متاحة

## 🛠️ التطوير

### التصحيح

```bash
# تشغيل الاختبارات
pytest

# فحص جودة الكود
flake8
black .
```

### النشر

```bash
# باستخدام Docker
docker build -t youtube-shorts-generator .
docker run -p 10000:10000 youtube-shorts-generator
```

## 📈 المساهمة

1. قم بعمل Fork للمشروع
2. أنشئ فرع للميزة: `git checkout -b feature/amazing-feature`
3. قم بعمل Commit للتغييرات: `git commit -m 'إضافة ميزة رائعة'`
4. ادفع إلى الفرع: `git push origin feature/amazing-feature`
5. افتح طلب Pull Request

## 📄 الترخيص

هذا المشروع مرخص تحت رخصة MIT - انظر ملف [LICENSE](LICENSE) للتفاصيل.

## 🙏 شكر خاص

- فريق ElevenLabs لواجهة API الصوت
- Google لنماذج الذكاء الاصطناعي
- مجتمع FastAPI المذهل

## 📞 الدعم

- افتح issue في GitHub
- راسلنا على support@yourdomain.com

## 🔐 الأمان

- استخدام JWT للمصادقة
- تشفير جميع البيانات الحساسة
- معالجة آمنة للملفات
- حماية من هجمات CSRF