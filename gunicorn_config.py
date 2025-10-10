# gunicorn_config.py
# This tells Gunicorn to use the right kind of worker for Socket.IO

bind = "0.0.0.0:10000"  # Bind to the port Render expects
workers = 1            # Start with 1 worker
threads = 4            # Number of threads per worker
worker_class = 'eventlet' # CRITICAL: This enables WebSocket support for Socket.IO
