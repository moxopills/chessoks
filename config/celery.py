"""Celery 설정"""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("chessok")

app.config_from_object("django.conf:settings", namespace="CELERY")

# 등록된 Django 앱에서 tasks.py 자동 검색
app.autodiscover_tasks()

# Beat 스케줄 설정
app.conf.beat_schedule = {
    "handle-game-timeouts": {
        "task": "apps.chess.tasks.handle_timeouts",
        "schedule": 2.0,  # 2초마다
    },
    "cleanup-stale-waiting-rooms": {
        "task": "apps.chess.tasks.cleanup_stale_waiting_rooms",
        "schedule": 180.0,  # 3분마다
    },
}
