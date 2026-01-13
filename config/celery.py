"""Celery 설정"""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("chessok")

app.config_from_object("django.conf:settings", namespace="CELERY")

# 등록된 Django 앱에서 tasks.py 자동 검색
app.autodiscover_tasks()
