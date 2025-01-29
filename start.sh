#!/bin/bash
set -e

# تعيين المنفذ الافتراضي إذا لم يكن محدداً
PORT="${PORT:-10000}"

# مجلد Prometheus
PROMETHEUS_DIR="${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus}"

# إنشاء المجلدات المطلوبة
mkdir -p logs temp "$PROMETHEUS_DIR"
chmod 777 temp "$PROMETHEUS_DIR"

echo "Starting server on port $PORT"

# تشغيل Gunicorn مباشرة مع bind
exec gunicorn \
    --bind "0.0.0.0:$PORT" \
    --workers ${WORKERS:-4} \
    --worker-class uvicorn.workers.UvicornWorker \
    --timeout ${TIMEOUT:-120} \
    --log-level ${LOG_LEVEL:-info} \
    --access-logfile - \
    --error-logfile - \
    app:app