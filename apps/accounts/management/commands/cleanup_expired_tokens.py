"""만료된 토큰 삭제 커맨드"""

from django.core.management.base import BaseCommand

from apps.accounts.models import EmailVerificationToken, PasswordResetToken


class Command(BaseCommand):
    help = "만료된 비밀번호 재설정 토큰 및 이메일 인증 토큰 삭제"

    def handle(self, *args, **options):
        # 비밀번호 재설정 토큰 삭제
        password_reset_count = PasswordResetToken.objects.delete_expired()

        # 이메일 인증 토큰 삭제
        email_verification_count = EmailVerificationToken.objects.delete_expired()

        self.stdout.write(
            self.style.SUCCESS(
                f"✅ 만료된 토큰 삭제 완료\n"
                f"   - 비밀번호 재설정: {password_reset_count}개\n"
                f"   - 이메일 인증: {email_verification_count}개"
            )
        )
