from rest_framework import serializers


class CommunityUserSerializer(serializers.Serializer):
    id = serializers.IntegerField(source="user.id")
    nickname = serializers.CharField(source="user.nickname")
    avatar_url = serializers.CharField(source="user.avatar_url", allow_blank=True, allow_null=True)
    rating = serializers.IntegerField(source="user.stats.rating", default=1200)
    featured_achievement_key = serializers.CharField(
        source="user.stats.featured_achievement_key",
        allow_blank=True,
        default="",
    )


class PlainUserSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    nickname = serializers.CharField()
    avatar_url = serializers.CharField(allow_blank=True, allow_null=True)
    rating = serializers.IntegerField(source="stats.rating", default=1200)
    featured_achievement_key = serializers.CharField(
        source="stats.featured_achievement_key",
        allow_blank=True,
        default="",
    )
