"""매칭 관련 Serializer"""

from rest_framework import serializers


class QuickMatchResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    room_id = serializers.IntegerField()
    game_id = serializers.IntegerField(allow_null=True)


class CancelMatchResponseSerializer(serializers.Serializer):
    cancelled = serializers.BooleanField()


class GameInviteCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(min_value=1)
    time_limit = serializers.IntegerField(min_value=1, max_value=180, required=False, default=10)
    room_id = serializers.IntegerField(min_value=1, required=False, allow_null=True)
