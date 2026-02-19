from django.core.cache import cache
from django.db.models import Q
from django.utils import timezone

from apps.accounts.models import User
from apps.adminpanel.models import Report


class AdminPanelService:
    @staticmethod
    def list_users(*, query: str | None, limit: int, offset: int):
        # 게스트 유저 제외
        qs = User.objects.filter(is_guest=False).select_related("stats").order_by("-date_joined")
        if query:
            qs = qs.filter(Q(email__icontains=query) | Q(nickname__icontains=query))
        total = qs.count()
        return total, list(qs[offset : offset + limit])

    @staticmethod
    def stats():
        cache_key = "adminpanel:stats:v1"
        cached = cache.get(cache_key)
        if cached:
            return cached
        now = timezone.now()
        # 게스트 유저 제외
        base_qs = User.objects.filter(is_guest=False)
        total_users = base_qs.count()
        active_users = base_qs.filter(is_active=True).count()
        suspended_qs = base_qs.filter(suspended_until__gt=now).order_by("-suspended_until")
        muted_qs = base_qs.filter(muted_until__gt=now).order_by("-muted_until")
        suspended_users = suspended_qs.count()
        muted_users = muted_qs.count()
        pending_reports = Report.objects.filter(status="pending").count()
        payload = {
            "total_users": total_users,
            "active_users": active_users,
            "suspended_users": suspended_users,
            "muted_users": muted_users,
            "pending_reports": pending_reports,
            "suspended_list": list(
                suspended_qs.values(
                    "id",
                    "nickname",
                    "suspended_until",
                    "suspension_reason",
                )[:20]
            ),
            "muted_list": list(
                muted_qs.values(
                    "id",
                    "nickname",
                    "muted_until",
                    "mute_reason",
                )[:20]
            ),
        }
        cache.set(cache_key, payload, timeout=10)
        return payload

    @staticmethod
    def list_reports(*, status: str | None, limit: int, offset: int):
        qs = Report.objects.select_related("reporter", "target", "resolved_by")
        if status:
            qs = qs.filter(status=status)
        total = qs.count()
        return total, list(qs[offset : offset + limit])
