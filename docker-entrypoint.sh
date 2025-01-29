#!/bin/bash
set -e

# Function to wait for Redis
wait_for_redis() {

    echo "Waiting for Redis at $redis_host:$redis_port..."
    while ! nc -z $redis_host $redis_port; do
        sleep 1
    done
    echo "Redis at $redis_host:$redis_port is up"
}

# Function to clean Redis data
clean_redis_data() {
    local redis_url=$1
    echo "Cleaning Redis data at $redis_url..."
    redis-cli -u "$redis_url" FLUSHDB
    echo "Redis data cleaned"
}

# Create necessary directories
mkdir -p logs temp static templates
chmod 777 temp

# Create cache directory for Prometheus metrics
mkdir -p "${PROMETHEUS_MULTIPROC_DIR:-/tmp}"
chmod 777 "${PROMETHEUS_MULTIPROC_DIR:-/tmp}"

# Wait for all Redis instances if enabled
if [ "${WAIT_FOR_REDIS}" = "true" ]; then
    wait_for_redis "${REDIS_MERNA_URL}"
    wait_for_redis "${REDIS_AQRABENO_URL}"
    wait_for_redis "${REDIS_SWALF_URL}"
    wait_for_redis "${REDIS_MOSAAD_URL}"
fi

# Clean Redis data if enabled
if [ "${CLEAN_REDIS_ON_START}" = "true" ]; then
    clean_redis_data "${REDIS_MERNA_URL}"
    clean_redis_data "${REDIS_AQRABENO_URL}"
    clean_redis_data "${REDIS_SWALF_URL}"
    clean_redis_data "${REDIS_MOSAAD_URL}"
fi

echo "Starting application with configuration:"
echo "Chain timeout: ${CHAIN_TIMEOUT:-600}s"
echo "Task timeout: ${TASK_TIMEOUT:-300}s"
echo "Workers: ${WORKERS:-4}"
echo "Log level: ${LOG_LEVEL:-info}"

exec "$@"