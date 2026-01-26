from rest_framework import serializers

from apps.accounts.models import Friend, FriendRequest
from apps.chess.serializers import PlayerSerializer


class FriendUserSerializer(PlayerSerializer):
    """친구 정보 (PlayerSerializer + win_rate)"""

    win_rate = serializers.FloatField(source="stats.win_rate", read_only=True)


class FriendSerializer(serializers.ModelSerializer):
    friend = FriendUserSerializer(read_only=True)

    class Meta:
        model = Friend
        fields = ("id", "friend", "created_at")


class FriendListSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = FriendSerializer(many=True, read_only=True)


class FriendRequestSerializer(serializers.ModelSerializer):
    from_user = FriendUserSerializer(read_only=True)
    to_user = FriendUserSerializer(read_only=True)

    class Meta:
        model = FriendRequest
        fields = ("id", "from_user", "to_user", "created_at")


class FriendRequestListSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = FriendRequestSerializer(many=True, read_only=True)


class FriendRequestCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(min_value=1)
