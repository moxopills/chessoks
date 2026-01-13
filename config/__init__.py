"""Django 시작 시 Celery 앱 로드"""

from .celery import app as celery_app

__all__ = ("celery_app",)
