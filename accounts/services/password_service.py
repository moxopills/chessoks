"""비밀번호 재설정 서비스"""

from datetime import timedelta

from django.contrib.auth import get_user_model
from django.utils import timezone

from accounts.models import PasswordResetToken
from accounts.utils.email import send_password_reset_email

User = get_user_model()


class PasswordResetService:
    """비밀번호 재설정 비즈니스 로직"""

    TOKEN_VALIDITY_HOURS = 1

    @classmethod
    def create_reset_token(cls, email):
        """재설정 토큰 생성 및 이메일 전송"""
        try:
            user = User.objects.get(email=email, is_active=True)
        except User.DoesNotExist:
            # 보안: 존재하지 않는 이메일도 동일하게 처리 (타이밍 공격 방지)
            return None

        # 기존 미사용 토큰 무효화
        PasswordResetToken.objects.filter(user=user, is_used=False).update(is_used=True)

        # 새 토큰 생성
        token = PasswordResetToken.objects.create(
            user=user,
            token=PasswordResetToken.generate_token(),
            expires_at=timezone.now() + timedelta(hours=cls.TOKEN_VALIDITY_HOURS),
        )

        # 이메일 전송
        send_password_reset_email(user.email, token.token)
        return token

    @classmethod
    def reset_password(cls, token_str, new_password):
        """토큰으로 비밀번호 재설정"""
        try:
            token = PasswordResetToken.objects.select_related("user").get(token=token_str)
        except PasswordResetToken.DoesNotExist:
            return False, "유효하지 않은 토큰입니다."

        if not token.is_valid:
            return False, "만료되었거나 이미 사용된 토큰입니다."

        # 비밀번호 변경
        user = token.user
        user.set_password(new_password)
        user.save(update_fields=["password"])

        # 토큰 사용 처리
        token.is_used = True
        token.used_at = timezone.now()
        token.save(update_fields=["is_used", "used_at"])

        return True, "비밀번호가 재설정되었습니다."
