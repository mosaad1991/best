import multiprocessing
import os

# Core Configuration
wsgi_app = "app:app"
bind = f"0.0.0.0:{os.environ['PORT']}"
workers = int(os.getenv('WORKERS', multiprocessing.cpu_count() * 2 + 1))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 120

# Logging
accesslog = "-"
errorlog = "-"
loglevel = os.getenv('LOG_LEVEL', 'info').lower()

# Server Mechanics
daemon = False
preload_app = True
reload = False