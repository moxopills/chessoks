"""이메일 전송 유틸리티"""

from django.conf import settings

from apps.accounts.tasks import send_email_task


def send_password_reset_email(user_email: str, token: str) -> None:
    """비밀번호 재설정 이메일 발송 (Celery 비동기)"""
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

    send_email_task.delay(user_email, subject, message)


def send_verification_email(user_email: str, token: str) -> None:
    """이메일 인증 메일 발송 (Celery 비동기)"""
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

    send_email_task.delay(user_email, subject, message)


def send_signup_verification_email(user_email: str, token: str) -> None:
    """회원가입 이메일 인증 메일 발송 (Celery 비동기)"""

    subject = "[ChessOK] 회원가입 이메일 인증"
    message = f"""
안녕하세요,

ChessOK 회원가입을 진행 중입니다.
아래 인증 코드를 입력하여 이메일 인증을 완료해주세요. (24시간 유효)

인증 코드: {token}

인증을 완료하시면 회원가입을 이어서 진행할 수 있습니다.

ChessOK 팀
    """

    send_email_task.delay(user_email, subject, message)
