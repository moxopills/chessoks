"""이메일 전송 유틸리티"""

from django.conf import settings
from django.core.mail import send_mail


def _send_template_email(user_email: str, subject: str, message: str) -> None:
    """공통 이메일 전송 함수

    Args:
        user_email: 수신자 이메일
        subject: 이메일 제목
        message: 이메일 본문
    """
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=False,
    )


def send_password_reset_email(user_email: str, token: str) -> None:
    """비밀번호 재설정 이메일 발송"""
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

    _send_template_email(user_email, subject, message)


def send_verification_email(user_email: str, token: str) -> None:
    """이메일 인증 메일 발송"""
    verification_url = f"{settings.FRONTEND_URL}/email-verification/confirm?token={token}"

    subject = "[ChessOK] 이메일 인증을 완료해주세요"
    message = f"""
안녕하세요,

ChessOK 회원가입을 환영합니다!
아래 링크를 클릭하여 이메일 인증을 완료해주세요. (24시간 유효)

{verification_url}

인증을 완료하시면 로그인이 가능합니다.

ChessOK 팀
    """

    _send_template_email(user_email, subject, message)
