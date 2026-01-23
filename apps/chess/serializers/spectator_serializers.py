from rest_framework import serializers

from apps.chess.serializers.game_serializers import BaseUserSerializer


class SpectatorListSerializer(serializers.Serializer):
    room_id = serializers.IntegerField(read_only=True)
    spectators = BaseUserSerializer(many=True, read_only=True)
