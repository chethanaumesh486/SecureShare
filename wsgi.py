"""Entry point for production servers (gunicorn). Does what `python server.py` does before it starts listening.

    gunicorn -w 1 -k gthread --threads 64 --timeout 120 -b 0.0.0.0:$PORT wsgi:app

Use exactly ONE worker (-w 1): logins, live-update subscribers and lockouts are kept in this process's memory.
"""
import server

server.init_db()
server.check_folders()
server.seed()
server.sync_manifests()
server.start_background()
with server.app.app_context():
    server.audit("SERVER_STARTED", "production (gunicorn)", actor="system")

app = server.app
