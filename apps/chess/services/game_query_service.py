from datetime import date

from django.db.models import Case, Count, IntegerField, Q, When

from rest_framework.exceptions import NotFound, ValidationError

import chess
from apps.chess.models import Game, Move


class GameQueryService:
    """게임 조회 관련 서비스"""

    WHITE_WIN_RESULTS = {
        Game.Status.WHITE_WIN,
        Game.Status.CHECKMATE_WHITE,
        Game.Status.TIMEOUT_BLACK,
        Game.Status.RESIGNATION_BLACK,
    }
    BLACK_WIN_RESULTS = {
        Game.Status.BLACK_WIN,
        Game.Status.CHECKMATE_BLACK,
        Game.Status.TIMEOUT_WHITE,
        Game.Status.RESIGNATION_WHITE,
    }

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
        color_order = Case(
            When(player_color="white", then=0),
            When(player_color="black", then=1),
            default=2,
            output_field=IntegerField(),
        )
        queryset = (
            Move.objects.filter(game=game)
            .annotate(color_order=color_order)
            .order_by("move_number", "color_order", "id")
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
    def list_legal_moves(game_id: int, user, from_square: str | None) -> list[str]:
        if not getattr(user, "is_authenticated", False):
            return []
        user_id = getattr(user, "pk", None)
        if user_id is None:
            return []
        try:
            game = Game.objects.select_related("room").get(pk=game_id)
        except Game.DoesNotExist:
            raise NotFound("게임을 찾을 수 없습니다.") from None
        if game.result != Game.Status.PLAYING:
            raise ValidationError({"game": "진행 중인 게임이 아닙니다."})
        if user_id not in {game.white_player_id, game.black_player_id}:
            return []
        if user_id not in {game.room.host_id, game.room.guest_id}:
            return []

        player_color = "white" if user_id == game.white_player_id else "black"
        if game.current_turn and game.current_turn != player_color:
            return []
        board = chess.Board(game.fen)
        board_turn = "white" if board.turn == chess.WHITE else "black"
        if game.current_turn and game.current_turn != board_turn:
            return []
        expected = chess.WHITE if player_color == "white" else chess.BLACK
        if board.turn != expected:
            return []

        legal_moves = [move.uci() for move in board.legal_moves]
        if from_square:
            from_square = from_square.strip().lower()
            if len(from_square) != 2:
                raise ValidationError({"from": "잘못된 좌표입니다."})
            legal_moves = [m for m in legal_moves if m.startswith(from_square)]
        return legal_moves

    @staticmethod
    def captured_summary(game_id: int, user) -> dict:
        """잡힌 기물 요약 조회 - captured_piece 필드 활용으로 최적화"""
        game = GameQueryService.get_game_for_user(game_id, user)

        # captured_piece 필드가 있는 경우 빠른 조회 (새 필드 활용)
        captures = (
            Move.objects.filter(game=game, is_capture=True)
            .exclude(captured_piece="")
            .values_list("captured_piece", "captured_color")
        )

        captured = {"white": [], "black": []}
        has_new_field_data = False

        for piece, color in captures:
            if piece and color:
                captured[color].append(piece)
                has_new_field_data = True

        # 새 필드에 데이터가 없는 경우 (기존 게임) fallback
        if not has_new_field_data:
            captured = GameQueryService._captured_summary_fallback(game)

        return captured

    @staticmethod
    def _captured_summary_fallback(game: Game) -> dict:
        """기존 게임용 fallback - 보드 재구성 방식"""
        color_order = Case(
            When(player_color="white", then=0),
            When(player_color="black", then=1),
            default=2,
            output_field=IntegerField(),
        )
        moves = (
            Move.objects.filter(game=game)
            .annotate(color_order=color_order)
            .order_by("move_number", "color_order", "id")
            .only("uci", "is_capture", "is_en_passant")
        )
        board = chess.Board()
        captured = {"white": [], "black": []}
        for move in moves:
            if move.is_capture:
                move_obj = chess.Move.from_uci(move.uci)
                capture_square = move_obj.to_square
                if move.is_en_passant:
                    offset = -8 if board.turn == chess.WHITE else 8
                    capture_square = move_obj.to_square + offset
                captured_piece = board.piece_at(capture_square)
                if captured_piece:
                    color = "white" if captured_piece.color == chess.WHITE else "black"
                    captured[color].append(captured_piece.symbol().upper())
            board.push(chess.Move.from_uci(move.uci))
        return captured

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
        no_count: bool = False,
    ) -> tuple[int, list[Game]]:
        queryset = (
            Game.objects.user_games(user)
            .select_related("room", "white_player__stats", "black_player__stats")
            .order_by("-created_at")
        )

        # 기본 전적에서는 AI 대전 제외
        if not room_type:
            queryset = queryset.exclude(room__room_type__startswith="ai_")

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
            if result in {"win", "lose", "draw"}:
                draw_results = {
                    Game.Status.DRAW,
                    Game.Status.STALEMATE,
                    Game.Status.DRAW_AGREEMENT,
                    Game.Status.DRAW_REPETITION,
                    Game.Status.DRAW_FIFTY_MOVE,
                    Game.Status.DRAW_INSUFFICIENT,
                }
                white_win_results = GameQueryService.WHITE_WIN_RESULTS
                black_win_results = GameQueryService.BLACK_WIN_RESULTS
                if result == "draw":
                    queryset = queryset.filter(result__in=draw_results)
                elif result == "win":
                    queryset = queryset.filter(
                        (Q(white_player=user) & Q(result__in=white_win_results))
                        | (Q(black_player=user) & Q(result__in=black_win_results))
                    )
                else:
                    queryset = queryset.filter(
                        (Q(white_player=user) & Q(result__in=black_win_results))
                        | (Q(black_player=user) & Q(result__in=white_win_results))
                    )
            else:
                valid_results = {choice[0] for choice in Game.Status.choices}
                if result not in valid_results:
                    raise ValidationError({"result": "유효하지 않은 결과입니다."})
                queryset = queryset.filter(result=result)
        else:
            queryset = queryset.exclude(result=Game.Status.PLAYING)

        if room_type:
            if room_type not in {"quick", "random", "custom", "ai_easy", "ai_medium", "ai_hard"}:
                raise ValidationError({"room_type": "유효하지 않은 방 타입입니다."})
            queryset = queryset.filter(room__room_type=room_type)

        games = list(queryset[offset : offset + limit])
        if no_count:
            return len(games), games
        total = queryset.count()
        return total, games

    @staticmethod
    def list_recent_for_user(user, *, limit: int) -> list[Game]:
        return list(
            Game.objects.user_games(user)
            .select_related("room", "white_player__stats", "black_player__stats")
            .exclude(result=Game.Status.PLAYING)
            .exclude(room__room_type__startswith="ai_")
            .order_by("-created_at")[:limit]
        )

    @staticmethod
    def head_to_head_summary(user, opponent) -> dict:
        """상대 전적 요약 - DB 집계 최적화"""
        white_win_results = GameQueryService.WHITE_WIN_RESULTS
        black_win_results = GameQueryService.BLACK_WIN_RESULTS
        draw_results = {
            Game.Status.DRAW,
            Game.Status.STALEMATE,
            Game.Status.DRAW_AGREEMENT,
            Game.Status.DRAW_REPETITION,
            Game.Status.DRAW_FIFTY_MOVE,
            Game.Status.DRAW_INSUFFICIENT,
        }

        base_qs = (
            Game.objects.filter(
                Q(white_player=user, black_player=opponent)
                | Q(white_player=opponent, black_player=user)
            )
            .exclude(result=Game.Status.PLAYING)
            .exclude(room__room_type__startswith="ai_")
        )

        # DB 레벨 집계 (Case/When + Count 사용)
        stats = base_qs.aggregate(
            total=Count("id"),
            wins=Count(
                "id",
                filter=(
                    Q(white_player=user, result__in=white_win_results)
                    | Q(black_player=user, result__in=black_win_results)
                ),
            ),
            losses=Count(
                "id",
                filter=(
                    Q(white_player=user, result__in=black_win_results)
                    | Q(black_player=user, result__in=white_win_results)
                ),
            ),
            draws=Count("id", filter=Q(result__in=draw_results)),
        )

        return {
            "total": stats["total"] or 0,
            "wins": stats["wins"] or 0,
            "losses": stats["losses"] or 0,
            "draws": stats["draws"] or 0,
        }

    @staticmethod
    def _outcome_for_user(game: Game, user) -> str:
        if game.result in GameQueryService.WHITE_WIN_RESULTS:
            return "win" if game.white_player_id == user.id else "loss"
        if game.result in GameQueryService.BLACK_WIN_RESULTS:
            return "win" if game.black_player_id == user.id else "loss"
        return "draw"

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
