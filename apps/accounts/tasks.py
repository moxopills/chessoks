"""Celery 비동기 태스크"""

import logging

from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from celery import shared_task

from apps.accounts.models import User

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_email_task(self, user_email: str, subject: str, message: str) -> bool:
    """이메일 전송 태스크 (재시도 지원)

    Args:
        user_email: 수신자 이메일
        subject: 이메일 제목
        message: 이메일 본문

    Returns:
        전송 성공 여부
    """
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user_email],
            fail_silently=False,
        )
        logger.info(f"이메일 전송 성공: {user_email}")
        return True
    except Exception as exc:
        logger.error(f"이메일 전송 실패: {user_email}, 에러: {exc}")
        raise self.retry(exc=exc) from exc


@shared_task
def cleanup_expired_tokens() -> int:
    """만료된 토큰 정리 (스케줄링용)

    Returns:
        삭제된 토큰 수
    """
    from apps.accounts.models import AuthToken

    deleted_count = AuthToken.objects.delete_expired()
    logger.info(f"만료된 토큰 {deleted_count}개 삭제 완료")
    return deleted_count


@shared_task
def cleanup_deleted_accounts() -> int:
    """탈퇴 예정 계정 정리 (스케줄링용)

    Returns:
        삭제된 계정 수
    """
    expired_accounts = User.objects.filter(
        is_active=False,
        scheduled_deletion_at__isnull=False,
        scheduled_deletion_at__lte=timezone.now(),
    )
    deleted_count, _ = expired_accounts.delete()
    logger.info(f"탈퇴 계정 {deleted_count}개 삭제 완료")
    return deleted_count


@shared_task
def cleanup_expired_sanctions() -> dict:
    """만료된 정지/뮤트 자동 해제"""
    now = timezone.now()
    unmuted = 0
    unsuspended = 0

    muted_users = User.objects.filter(muted_until__isnull=False, muted_until__lte=now)
    for user in muted_users:
        user.muted_until = None
        user.mute_reason = ""
        user.save(update_fields=["muted_until", "mute_reason"])
        from apps.notifications.services import NotificationService

        NotificationService.create_notification(
            user=user,
            type="chat_unmute",
            title="채팅 제한 해제",
            message="채팅 제한이 해제되었습니다.",
            payload={},
        )
        unmuted += 1

    suspended_users = User.objects.filter(suspended_until__isnull=False, suspended_until__lte=now)
    for user in suspended_users:
        user.suspended_until = None
        user.suspension_reason = ""
        user.save(update_fields=["suspended_until", "suspension_reason"])
        from apps.notifications.services import NotificationService

        NotificationService.create_notification(
            user=user,
            type="account_unsuspended",
            title="계정 정지 해제",
            message="계정 정지가 해제되었습니다.",
            payload={},
        )
        unsuspended += 1

    logger.info(
        "정지/뮤트 자동 해제 완료: chat_unmute=%s, account_unsuspended=%s",
        unmuted,
        unsuspended,
    )
    return {"unmuted": unmuted, "unsuspended": unsuspended}
