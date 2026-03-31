from rest_framework import serializers

from apps.accounts.services.achievement_service import AchievementService


def _avatar_with_cache_bust(user) -> str | None:
    if user is None:
        return None
    url = getattr(user, "avatar_url", None)
    if not url:
        return None
    updated_at = getattr(user, "updated_at", None)
    if not updated_at:
        return url
    version = int(updated_at.timestamp())
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}v={version}"


class BaseUserSerializer(serializers.Serializer):
    """사용자 기본 정보 (관전자 등)"""

    id = serializers.IntegerField(read_only=True)
    nickname = serializers.CharField(read_only=True)
    avatar_url = serializers.SerializerMethodField()
    nickname_color = serializers.SerializerMethodField()
    profile_border = serializers.SerializerMethodField()
    selected_board_skin_class = serializers.SerializerMethodField()
    selected_piece_skin_class = serializers.SerializerMethodField()
    featured_achievement = serializers.SerializerMethodField()

    def get_avatar_url(self, obj):
        return _avatar_with_cache_bust(obj)

    def get_nickname_color(self, obj):
        return getattr(getattr(obj, "stats", None), "nickname_color", "")

    def get_profile_border(self, obj):
        return getattr(getattr(obj, "stats", None), "profile_border", "")

    def get_selected_board_skin_class(self, obj):
        return getattr(
            getattr(obj, "stats", None), "selected_board_skin_class", "skin-board-classic"
        )

    def get_selected_piece_skin_class(self, obj):
        return getattr(
            getattr(obj, "stats", None), "selected_piece_skin_class", "skin-piece-classic"
        )

    def get_featured_achievement(self, obj):
        return AchievementService.get_featured_achievement_for_stats(getattr(obj, "stats", None))


class PlayerSerializer(BaseUserSerializer):
    """플레이어 정보 (레이팅 포함)"""

    rating = serializers.IntegerField(source="stats.rating", read_only=True)
    rank_tier = serializers.CharField(source="stats.rank_tier", read_only=True)


class MoveSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    move_number = serializers.IntegerField(read_only=True)
    player_color = serializers.CharField(read_only=True)
    piece = serializers.CharField(read_only=True)
    from_square = serializers.CharField(read_only=True)
    to_square = serializers.CharField(read_only=True)
    san = serializers.CharField(read_only=True)
    uci = serializers.CharField(read_only=True)
    is_capture = serializers.BooleanField(read_only=True)
    is_check = serializers.BooleanField(read_only=True)
    is_checkmate = serializers.BooleanField(read_only=True)
    is_castling = serializers.BooleanField(read_only=True)
    is_en_passant = serializers.BooleanField(read_only=True)
    promotion = serializers.CharField(read_only=True, allow_blank=True)
    fen_after_move = serializers.CharField(read_only=True)
    time_spent = serializers.FloatField(read_only=True, allow_null=True)
    created_at = serializers.DateTimeField(read_only=True)


class BaseGameSerializer(serializers.Serializer):
    """게임 공통 필드"""

    id = serializers.IntegerField(read_only=True)
    room_id = serializers.IntegerField(read_only=True)
    white_player = PlayerSerializer(read_only=True)
    black_player = PlayerSerializer(read_only=True)
    result = serializers.CharField(read_only=True)
    move_count = serializers.IntegerField(read_only=True)
    started_at = serializers.DateTimeField(read_only=True, allow_null=True)
    finished_at = serializers.DateTimeField(read_only=True, allow_null=True)
    created_at = serializers.DateTimeField(read_only=True)


class GameDetailSerializer(BaseGameSerializer):
    """게임 상세 - 진행 중 정보 포함"""

    fen = serializers.CharField(read_only=True)
    pgn = serializers.CharField(read_only=True)
    current_turn = serializers.CharField(read_only=True)
    white_time_remaining = serializers.IntegerField(read_only=True)
    black_time_remaining = serializers.IntegerField(read_only=True)
    turn_started_at = serializers.DateTimeField(read_only=True, allow_null=True)


class GameHistorySerializer(BaseGameSerializer):
    """전적 목록 - 방 타입 포함"""

    room_type = serializers.CharField(source="room.room_type", read_only=True)


class PagedMoveSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = MoveSerializer(many=True, read_only=True)


class PagedGameHistorySerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = GameHistorySerializer(many=True, read_only=True)
