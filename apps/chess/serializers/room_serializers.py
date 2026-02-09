from rest_framework import serializers

from apps.chess.serializers.game_serializers import PlayerSerializer


class RoomSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    room_type = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    current_game_id = serializers.SerializerMethodField()
    is_private = serializers.BooleanField(read_only=True)
    allow_spectators = serializers.BooleanField(read_only=True)
    time_limit = serializers.IntegerField(read_only=True)
    increment_seconds = serializers.IntegerField(read_only=True)
    host = PlayerSerializer(read_only=True)
    guest = PlayerSerializer(read_only=True, allow_null=True)
    host_ready = serializers.BooleanField(read_only=True)
    guest_ready = serializers.BooleanField(read_only=True)
    host_start_confirmed = serializers.BooleanField(read_only=True)
    guest_start_confirmed = serializers.BooleanField(read_only=True)
    player_count = serializers.IntegerField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)
    started_at = serializers.DateTimeField(read_only=True, allow_null=True)
    finished_at = serializers.DateTimeField(read_only=True, allow_null=True)

    def get_current_game_id(self, room):
        annotated = getattr(room, "current_game_id_annotated", None)
        if annotated:
            return annotated
        game = room.games.filter(result="playing").only("id", "created_at").first()
        if game:
            return game.id
        if room.status == "playing":
            latest = room.games.only("id").order_by("-created_at").first()
            return latest.id if latest else None
        return None


class PagedRoomSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = RoomSerializer(many=True, read_only=True)


class RoomCreateRequestSerializer(serializers.Serializer):
    room_type = serializers.ChoiceField(choices=["quick", "custom"], default="custom")
    title = serializers.CharField(max_length=100, required=False, allow_blank=True)
    time_limit = serializers.IntegerField(min_value=0, max_value=60, default=15)
    increment_seconds = serializers.IntegerField(min_value=0, max_value=60, default=10)
    password = serializers.CharField(max_length=50, required=False, allow_blank=True)
    allow_spectators = serializers.BooleanField(default=True)
