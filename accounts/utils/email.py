"""이메일 전송 유틸리티"""

from django.conf import settings
from django.core.mail import send_mail


def send_password_reset_email(user_email, token):
    """비밀번호 재설정 이메일 전송"""
    reset_url = f"{settings.FRONTEND_URL}/password-reset/confirm?token={token}"

    subject = "[ChessOK] 비밀번호 재설정 요청"
    message = f"""
안녕하세요,

비밀번호 재설정을 요청하셨습니다.
아래 링크를 클릭하여 비밀번호를 재설정하세요. (1시간 유효)

{reset_url}

요청하지 않으셨다면 이 메일을 무시하세요.

ChessOK 팀
    """

    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=False,
    )
