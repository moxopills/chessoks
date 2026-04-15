from rest_framework import serializers

from apps.community.models import (
    Guild,
    GuildAuditLog,
    GuildChatMessage,
    GuildJoinRequest,
    GuildMember,
)

from .common import PlainUserSerializer


class GuildCreateSerializer(serializers.Serializer):
    name = serializers.CharField(max_length=40)
    avatar = serializers.ImageField(required=False, allow_null=True)
    description = serializers.CharField(required=False, allow_blank=True)
    join_policy = serializers.ChoiceField(choices=Guild.JoinPolicy.choices)
    min_rating = serializers.IntegerField(min_value=0, max_value=4000, required=False, default=0)
    active_hours = serializers.CharField(max_length=80, required=False, allow_blank=True)
    contact_channel = serializers.CharField(max_length=80, required=False, allow_blank=True)


class GuildMemberSerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = GuildMember
        fields = ["user", "role", "joined_at"]


class GuildSerializer(serializers.ModelSerializer):
    owner = PlainUserSerializer(read_only=True)
    pending_requests = serializers.SerializerMethodField()

    def get_pending_requests(self, obj):
        return getattr(obj, "pending_requests", 0)

    class Meta:
        model = Guild
        fields = [
            "id",
            "name",
            "slug",
            "avatar_url",
            "description",
            "notice",
            "join_policy",
            "min_rating",
            "active_hours",
            "contact_channel",
            "team_rating",
            "member_count",
            "created_at",
            "owner",
            "pending_requests",
        ]


class GuildDetailSerializer(GuildSerializer):
    members = GuildMemberSerializer(many=True, read_only=True)

    class Meta(GuildSerializer.Meta):
        fields = GuildSerializer.Meta.fields + ["members"]


class GuildJoinRequestCreateSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=200, required=False, allow_blank=True)


class GuildJoinRequestReviewSerializer(serializers.Serializer):
    approve = serializers.BooleanField()


class GuildJoinRequestSerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = GuildJoinRequest
        fields = ["id", "status", "message", "created_at", "reviewed_at", "user"]


class GuildMemberRoleSerializer(serializers.Serializer):
    role = serializers.ChoiceField(choices=GuildMember.Role.choices)


class GuildAvatarUpdateSerializer(serializers.Serializer):
    avatar = serializers.ImageField(required=True)


class GuildChatCreateSerializer(serializers.Serializer):
    content = serializers.CharField(max_length=500)


class GuildChatMessageSerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = GuildChatMessage
        fields = ["id", "content", "created_at", "user"]


class GuildAuditLogSerializer(serializers.ModelSerializer):
    actor = PlainUserSerializer(read_only=True)
    target_user = PlainUserSerializer(read_only=True)

    class Meta:
        model = GuildAuditLog
        fields = ["id", "action", "detail", "created_at", "actor", "target_user"]
