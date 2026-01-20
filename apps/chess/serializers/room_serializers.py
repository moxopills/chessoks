from rest_framework import serializers

from apps.chess.serializers.game_serializers import PlayerSerializer


class RoomSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    room_type = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    is_private = serializers.BooleanField(read_only=True)
    allow_spectators = serializers.BooleanField(read_only=True)
    time_limit = serializers.IntegerField(read_only=True)
    increment_seconds = serializers.IntegerField(read_only=True)
    host = PlayerSerializer(read_only=True)
    guest = PlayerSerializer(read_only=True, allow_null=True)
    player_count = serializers.IntegerField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    started_at = serializers.DateTimeField(read_only=True, allow_null=True)
    finished_at = serializers.DateTimeField(read_only=True, allow_null=True)


class PagedRoomSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = RoomSerializer(many=True, read_only=True)
