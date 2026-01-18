"""매칭 관련 Serializer"""

from rest_framework import serializers


class QuickMatchResponseSerializer(serializers.Serializer):
    status = serializers.CharField()
    room_id = serializers.IntegerField()
    game_id = serializers.IntegerField(allow_null=True)


class CancelMatchResponseSerializer(serializers.Serializer):
    cancelled = serializers.BooleanField()
