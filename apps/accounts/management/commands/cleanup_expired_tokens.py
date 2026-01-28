"""만료된 토큰 삭제 커맨드"""

from django.core.management.base import BaseCommand

from apps.accounts.models import AuthToken, SignupEmailToken


class Command(BaseCommand):
    help = "만료된 인증 토큰 삭제 (이메일 인증, 비밀번호 재설정)"

    def handle(self, *args, **options):
        # 전체 만료 토큰 삭제
        deleted_count = AuthToken.objects.delete_expired()
        signup_deleted_count = SignupEmailToken.objects.delete_expired()

        total = deleted_count + signup_deleted_count
        self.stdout.write(self.style.SUCCESS(f"만료된 토큰 {total}개 삭제 완료"))
