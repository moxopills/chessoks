"""Celery 설정"""

import os

from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

app = Celery("chessok")

app.config_from_object("django.conf:settings", namespace="CELERY")

# 등록된 Django 앱에서 tasks.py 자동 검색
app.autodiscover_tasks()

# Beat 스케줄 설정 (모든 주기 작업)
app.conf.beat_schedule = {
    # === 게임 관련 ===
    "handle-game-timeouts": {
        "task": "apps.chess.tasks.handle_timeouts",
        "schedule": 2.0,  # 2초마다
    },
    "cleanup-stale-waiting-rooms": {
        "task": "apps.chess.tasks.cleanup_stale_waiting_rooms",
        "schedule": 60.0,  # 1분마다
        "args": [3],  # 3분 이상 대기방 정리
    },
    "cleanup-inactive-rooms": {
        "task": "apps.chess.tasks.cleanup_inactive_rooms",
        "schedule": 300.0,  # 5분마다
        "args": [15],  # 15분 이상 유휴 방 정리
    },
    "cleanup-lobby-messages": {
        "task": "apps.chess.tasks.cleanup_lobby_messages",
        "schedule": 86400.0,  # 매일 (24시간)
        "args": [1],  # 1일 이상 메시지 삭제
    },
    # === 계정 관련 ===
    "cleanup-expired-tokens": {
        "task": "apps.accounts.tasks.cleanup_expired_tokens",
        "schedule": 86400.0,  # 매일 (24시간)
    },
    "cleanup-deleted-accounts": {
        "task": "apps.accounts.tasks.cleanup_deleted_accounts",
        "schedule": 86400.0,  # 매일 (24시간)
    },
}
