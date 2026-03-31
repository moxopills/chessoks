from rest_framework import serializers


class FeaturedAchievementSerializer(serializers.Serializer):
    key = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    icon = serializers.CharField(read_only=True)
    tone = serializers.CharField(read_only=True)


class OnlineStatusSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    online = serializers.BooleanField(read_only=True)
    status = serializers.CharField(read_only=True)
    status_label = serializers.CharField(read_only=True)
    room_id = serializers.IntegerField(read_only=True, allow_null=True)
    game_id = serializers.IntegerField(read_only=True, allow_null=True)


class PresenceUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["online", "room_waiting", "puzzle"])
    active = serializers.BooleanField(required=False, default=True)
    room_id = serializers.IntegerField(required=False, allow_null=True)
    game_id = serializers.IntegerField(required=False, allow_null=True)
    scope_id = serializers.CharField(required=False, allow_blank=True, max_length=80)


class OnlineStatusListSerializer(serializers.Serializer):
    results = OnlineStatusSerializer(many=True, read_only=True)


class OnlineUserSummarySerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    nickname = serializers.CharField(read_only=True)
    avatar_url = serializers.CharField(read_only=True, allow_null=True)
    rank_tier = serializers.CharField(read_only=True)
    nickname_color = serializers.CharField(read_only=True, allow_blank=True)
    profile_border = serializers.CharField(read_only=True, allow_blank=True)
    online = serializers.BooleanField(read_only=True)
    status = serializers.CharField(read_only=True)
    status_label = serializers.CharField(read_only=True)
    room_id = serializers.IntegerField(read_only=True, allow_null=True)
    game_id = serializers.IntegerField(read_only=True, allow_null=True)
    featured_achievement = FeaturedAchievementSerializer(read_only=True, allow_null=True)


class OnlineUsersListSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = OnlineUserSummarySerializer(many=True, read_only=True)
