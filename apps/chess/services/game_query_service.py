from datetime import date

from django.db.models import Q

from rest_framework.exceptions import NotFound, ValidationError

from apps.chess.models import Game, Move


class GameQueryService:
    """게임 조회 관련 서비스"""

    @staticmethod
    def get_game_for_user(game_id: int, user) -> Game:
        try:
            game = Game.objects.select_related(
                "room", "white_player__stats", "black_player__stats"
            ).get(pk=game_id)
        except Game.DoesNotExist:
            raise NotFound("게임을 찾을 수 없습니다.") from None

        if not GameQueryService._has_access(game, user):
            raise NotFound("게임 접근 권한이 없습니다.")
        return game

    @staticmethod
    def list_moves(game_id: int, user, limit: int, offset: int) -> tuple[int, list[Move]]:
        game = GameQueryService.get_game_for_user(game_id, user)
        queryset = (
            Move.objects.filter(game=game)
            .order_by("move_number", "player_color", "id")
            .only(
                "id",
                "move_number",
                "player_color",
                "piece",
                "from_square",
                "to_square",
                "san",
                "uci",
                "is_capture",
                "is_check",
                "is_checkmate",
                "is_castling",
                "is_en_passant",
                "promotion",
                "fen_after_move",
                "time_spent",
                "created_at",
            )
        )
        total = queryset.count()
        return total, list(queryset[offset : offset + limit])

    @staticmethod
    def _has_access(game: Game, user) -> bool:
        room = game.room
        if user == game.white_player or user == game.black_player:
            return True
        if room.allow_spectators:
            return True
        return room.spectators.filter(pk=user.pk).exists()

    # ========== 전적 조회 ==========

    @staticmethod
    def list_history(
        user,
        *,
        opponent: str | None,
        start_date: str | None,
        end_date: str | None,
        result: str | None,
        room_type: str | None,
        limit: int,
        offset: int,
    ) -> tuple[int, list[Game]]:
        queryset = (
            Game.objects.user_games(user)
            .select_related("room", "white_player__stats", "black_player__stats")
            .order_by("-created_at")
        )

        if opponent:
            queryset = queryset.filter(GameQueryService._opponent_filter(user, opponent))

        if start_date or end_date:
            start = GameQueryService._parse_date(start_date, "start_date") if start_date else None
            end = GameQueryService._parse_date(end_date, "end_date") if end_date else None
            if start and end and start > end:
                raise ValidationError({"date": "start_date는 end_date보다 클 수 없습니다."})
            if start:
                queryset = queryset.filter(created_at__date__gte=start)
            if end:
                queryset = queryset.filter(created_at__date__lte=end)

        if result:
            valid_results = {choice[0] for choice in Game.RESULT_CHOICES}
            if result not in valid_results:
                raise ValidationError({"result": "유효하지 않은 결과입니다."})
            queryset = queryset.filter(result=result)
        else:
            queryset = queryset.exclude(result="playing")

        if room_type:
            if room_type not in {"quick", "custom"}:
                raise ValidationError({"room_type": "유효하지 않은 방 타입입니다."})
            queryset = queryset.filter(room__room_type=room_type)

        total = queryset.count()
        return total, list(queryset[offset : offset + limit])

    @staticmethod
    def _opponent_filter(user, opponent: str):
        opponent = opponent.strip()
        if opponent.isdigit():
            opponent_id = int(opponent)
            return Q(white_player=user, black_player_id=opponent_id) | Q(
                black_player=user, white_player_id=opponent_id
            )
        return Q(white_player=user, black_player__nickname__icontains=opponent) | Q(
            black_player=user, white_player__nickname__icontains=opponent
        )

    @staticmethod
    def _parse_date(value: str, field_name: str) -> date:
        try:
            return date.fromisoformat(value)
        except ValueError as exc:
            raise ValidationError({field_name: "YYYY-MM-DD 형식이어야 합니다."}) from exc
