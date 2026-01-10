"""만료된 탈퇴 예약 계정 삭제 커맨드"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from apps.accounts.models import User


class Command(BaseCommand):
    help = "유예 기간이 만료된 탈퇴 예약 계정 삭제"

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="실제 삭제 없이 대상 계정만 확인",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        now = timezone.now()

        # 유예 기간 만료된 계정 조회
        expired_accounts = User.objects.filter(
            is_active=False,
            scheduled_deletion_at__isnull=False,
            scheduled_deletion_at__lte=now,
        )

        count = expired_accounts.count()

        if count == 0:
            self.stdout.write(self.style.SUCCESS("삭제할 계정이 없습니다."))
            return

        if dry_run:
            self.stdout.write(self.style.WARNING(f"[DRY-RUN] 삭제 대상 계정: {count}개"))
            for user in expired_accounts[:10]:
                self.stdout.write(f"  - {user.email} (예정일: {user.scheduled_deletion_at})")
            if count > 10:
                self.stdout.write(f"  ... 외 {count - 10}개")
        else:
            deleted_count, _ = expired_accounts.delete()
            self.stdout.write(
                self.style.SUCCESS(f"✅ 만료된 탈퇴 예약 계정 {deleted_count}개 삭제 완료")
            )
