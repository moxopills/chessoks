from rest_framework import serializers

from apps.accounts.models import User, UserStats
from apps.adminpanel.models import Report


class AdminUserSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    email = serializers.EmailField(read_only=True)
    nickname = serializers.CharField(read_only=True)
    rating = serializers.IntegerField(read_only=True)
    rank_tier = serializers.CharField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    is_staff = serializers.BooleanField(read_only=True)
    is_superuser = serializers.BooleanField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True, allow_null=True)
    suspended_until = serializers.DateTimeField(read_only=True, allow_null=True)
    muted_until = serializers.DateTimeField(read_only=True, allow_null=True)

    def to_representation(self, instance: User):
        data = super().to_representation(instance)
        stats: UserStats | None = getattr(instance, "stats", None)
        data["rating"] = stats.rating if stats else 1200
        data["rank_tier"] = stats.rank_tier if stats else "Junior"
        return data


class AdminUserListSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = AdminUserSerializer(many=True, read_only=True)


class PromoteSerializer(serializers.Serializer):
    is_staff = serializers.BooleanField(default=True)
    is_superuser = serializers.BooleanField(default=False)


class SuspendSerializer(serializers.Serializer):
    days = serializers.IntegerField(min_value=1, max_value=365, required=False)
    until = serializers.DateTimeField(required=False)
    reason = serializers.CharField(max_length=200, required=False, allow_blank=True)

    def validate(self, attrs):
        if not attrs.get("days") and not attrs.get("until"):
            raise serializers.ValidationError("days 또는 until 값이 필요합니다.")
        return attrs


class MuteSerializer(serializers.Serializer):
    minutes = serializers.IntegerField(min_value=1, max_value=10080, required=False)
    until = serializers.DateTimeField(required=False)
    reason = serializers.CharField(max_length=200, required=False, allow_blank=True)

    def validate(self, attrs):
        if not attrs.get("minutes") and not attrs.get("until"):
            raise serializers.ValidationError("minutes 또는 until 값이 필요합니다.")
        return attrs


class NoticeSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=100)
    message = serializers.CharField(max_length=255)


class AdminStatsSerializer(serializers.Serializer):
    total_users = serializers.IntegerField(read_only=True)
    active_users = serializers.IntegerField(read_only=True)
    suspended_users = serializers.IntegerField(read_only=True)
    muted_users = serializers.IntegerField(read_only=True)
    pending_reports = serializers.IntegerField(read_only=True)
    suspended_list = serializers.ListField(read_only=True)
    muted_list = serializers.ListField(read_only=True)


class ReportSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    reporter_id = serializers.IntegerField(read_only=True, allow_null=True)
    reporter_nickname = serializers.CharField(read_only=True, allow_blank=True)
    target_id = serializers.IntegerField(read_only=True)
    target_nickname = serializers.CharField(read_only=True)
    category = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    resolution_note = serializers.CharField(read_only=True, allow_blank=True)
    resolved_by_id = serializers.IntegerField(read_only=True, allow_null=True)
    resolved_at = serializers.DateTimeField(read_only=True, allow_null=True)
    created_at = serializers.DateTimeField(read_only=True)


class ReportCreateSerializer(serializers.Serializer):
    target_id = serializers.IntegerField()
    category = serializers.ChoiceField(choices=Report.CATEGORY_CHOICES)
    description = serializers.CharField(max_length=500, required=False, allow_blank=True)


class ReportResolveSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=Report.STATUS_CHOICES)
    resolution_note = serializers.CharField(max_length=500, required=False, allow_blank=True)

    def validate_status(self, value):
        if value == "pending":
            raise serializers.ValidationError("pending 상태로는 처리할 수 없습니다.")
        return value
