"""만료된 비밀번호 재설정 토큰 삭제 커맨드"""

from django.core.management.base import BaseCommand

from apps.accounts.models import PasswordResetToken


class Command(BaseCommand):
    help = "만료된 비밀번호 재설정 토큰 삭제"

    def handle(self, *args, **options):
        deleted_count = PasswordResetToken.objects.delete_expired()

        self.stdout.write(self.style.SUCCESS(f"✅ 만료된 토큰 {deleted_count}개 삭제 완료"))
