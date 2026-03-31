import random
from datetime import timedelta

from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.db.models import Avg, Count, F, Q
from django.utils import timezone

from rest_framework.exceptions import ValidationError

import chess
from apps.chess.models import DailyPuzzle, Puzzle, UserPuzzleAttempt


class PuzzleService:
    """일일 퍼즐 서비스"""

    LEVEL_EASY = "easy"
    LEVEL_MEDIUM = "medium"
    LEVEL_HARD = "hard"
    LEVEL_DEFAULT = LEVEL_MEDIUM
    LEVEL_LABELS = {
        LEVEL_EASY: "쉬움",
        LEVEL_MEDIUM: "중간",
        LEVEL_HARD: "어려움",
    }
    LEVEL_RATING_BANDS = {
        LEVEL_EASY: (800, 1199),
        LEVEL_MEDIUM: (1200, 1799),
        LEVEL_HARD: (1800, 2600),
    }
    ALL_LEVELS = (LEVEL_EASY, LEVEL_MEDIUM, LEVEL_HARD)

    DAILY_RECENT_EXCLUDE_DAYS = 30
    DAILY_SAMPLE_SIZE = 1000
    HINT_LIMIT = 3
    GUEST_STATE_TTL_SECONDS = 60 * 60 * 24 * 3
    DAILY_PUZZLE_CACHE_TTL_SECONDS = 60 * 5
    USER_METRICS_CACHE_TTL_SECONDS = 60 * 5
    MSG_NO_PUZZLE_DATA = "현재 사용할 수 있는 퍼즐이 없습니다. 잠시 후 다시 시도해주세요."
    MSG_INVALID_MOVE_FORMAT = "수 입력 형식이 올바르지 않습니다. 예: e2e4"
    MSG_INVALID_PUZZLE_DATA = "퍼즐 데이터가 올바르지 않습니다. 관리자에게 문의해주세요."
    MSG_ILLEGAL_MOVE = "둘 수 없는 수입니다. 말의 이동 규칙을 다시 확인해주세요."
    MSG_HINT_LIMIT_REACHED = "힌트는 하루 최대 3번까지 사용할 수 있습니다."
    MSG_INVALID_LEVEL = "난이도는 쉬움(easy), 중간(medium), 어려움(hard) 중에서 선택해주세요."
    PIECE_KR = {
        chess.PAWN: "폰",
        chess.KNIGHT: "나이트",
        chess.BISHOP: "비숍",
        chess.ROOK: "룩",
        chess.QUEEN: "퀸",
        chess.KING: "킹",
    }

    @staticmethod
    def normalize_level(level: str | None) -> str:
        normalized = (level or PuzzleService.LEVEL_DEFAULT).strip().lower()
        if normalized not in PuzzleService.ALL_LEVELS:
            raise ValidationError({"level": PuzzleService.MSG_INVALID_LEVEL})
        return normalized

    @staticmethod
    def get_or_create_daily_puzzle(*, level: str | None = None, today=None) -> DailyPuzzle:
        level = PuzzleService.normalize_level(level)
        today = today or timezone.localdate()
        cache_key = PuzzleService._daily_cache_key(level=level, today=today)
        cached_id = cache.get(cache_key)
        if cached_id:
            cached_daily = (
                DailyPuzzle.objects.select_related("puzzle")
                .filter(id=cached_id, date=today, level=level)
                .first()
            )
            if cached_daily:
                return cached_daily
        daily = DailyPuzzle.objects.select_related("puzzle").filter(date=today, level=level).first()
        if daily:
            cache.set(cache_key, daily.id, PuzzleService.DAILY_PUZZLE_CACHE_TTL_SECONDS)
            return daily
        daily = PuzzleService.select_daily_puzzle(level=level, today=today)
        cache.set(cache_key, daily.id, PuzzleService.DAILY_PUZZLE_CACHE_TTL_SECONDS)
        return daily

    @staticmethod
    def select_daily_puzzle(*, level: str | None = None, today=None) -> DailyPuzzle:
        level = PuzzleService.normalize_level(level)
        today = today or timezone.localdate()
        min_rating, max_rating = PuzzleService.LEVEL_RATING_BANDS[level]
        with transaction.atomic():
            existing = (
                DailyPuzzle.objects.select_for_update().filter(date=today, level=level).first()
            )
            if existing:
                return existing

            recent_ids = DailyPuzzle.objects.filter(
                date__gte=today - timedelta(days=PuzzleService.DAILY_RECENT_EXCLUDE_DAYS),
                level=level,
            ).values_list("puzzle_id", flat=True)

            candidate_ids = PuzzleService._pick_candidate_ids(
                min_rating=min_rating,
                max_rating=max_rating,
                recent_ids=recent_ids,
            )
            if not candidate_ids:
                raise ValidationError(PuzzleService.MSG_NO_PUZZLE_DATA)

            selected_id = random.choice(candidate_ids)
            try:
                daily = DailyPuzzle.objects.create(date=today, level=level, puzzle_id=selected_id)
            except IntegrityError:
                # 레이스 컨디션: 다른 워커가 먼저 생성
                daily = (
                    DailyPuzzle.objects.select_related("puzzle")
                    .filter(date=today, level=level)
                    .first()
                )
                if not daily:
                    raise
            cache.set(
                PuzzleService._daily_cache_key(level=level, today=today),
                daily.id,
                PuzzleService.DAILY_PUZZLE_CACHE_TTL_SECONDS,
            )
            return daily

    @staticmethod
    def _pick_candidate_ids(*, min_rating: int, max_rating: int, recent_ids) -> list[int]:
        """난이도 구간 후보가 없을 때 전체 풀로 폴백한다."""
        # 1) 난이도 구간 + 최근 제외
        ids = list(
            Puzzle.objects.filter(rating__gte=min_rating, rating__lte=max_rating)
            .exclude(id__in=recent_ids)
            .values_list("id", flat=True)[: PuzzleService.DAILY_SAMPLE_SIZE]
        )
        if ids:
            return ids

        # 2) 난이도 구간 전체
        ids = list(
            Puzzle.objects.filter(rating__gte=min_rating, rating__lte=max_rating).values_list(
                "id", flat=True
            )[: PuzzleService.DAILY_SAMPLE_SIZE]
        )
        if ids:
            return ids

        # 3) 전체 풀 + 최근 제외
        ids = list(
            Puzzle.objects.exclude(id__in=recent_ids).values_list("id", flat=True)[
                : PuzzleService.DAILY_SAMPLE_SIZE
            ]
        )
        if ids:
            return ids

        # 4) 전체 풀
        return list(Puzzle.objects.values_list("id", flat=True)[: PuzzleService.DAILY_SAMPLE_SIZE])

    @staticmethod
    def get_daily_with_attempt(user, *, level: str | None = None):
        level = PuzzleService.normalize_level(level)
        daily = PuzzleService.get_or_create_daily_puzzle(level=level)
        attempt = None
        if getattr(user, "is_authenticated", False) and not getattr(user, "is_guest", False):
            attempt = PuzzleService._get_or_create_attempt(user=user, daily=daily)
        return daily, attempt

    @staticmethod
    def submit_move(*, user, move_uci: str, level: str | None = None) -> dict:
        level = PuzzleService.normalize_level(level)
        daily = PuzzleService.get_or_create_daily_puzzle(level=level)
        puzzle = daily.puzzle
        move_uci = (move_uci or "").strip().lower()
        if len(move_uci) < 4:
            raise ValidationError({"move": PuzzleService.MSG_INVALID_MOVE_FORMAT})

        if getattr(user, "is_authenticated", False) and not getattr(user, "is_guest", False):
            return PuzzleService._submit_move_for_user(
                user=user, daily=daily, puzzle=puzzle, move_uci=move_uci
            )
        return PuzzleService._submit_move_for_guest(
            user=user, daily=daily, puzzle=puzzle, move_uci=move_uci
        )

    @staticmethod
    def request_hint(*, user, level: str | None = None) -> dict:
        level = PuzzleService.normalize_level(level)
        daily = PuzzleService.get_or_create_daily_puzzle(level=level)
        puzzle = daily.puzzle
        if getattr(user, "is_authenticated", False) and not getattr(user, "is_guest", False):
            return PuzzleService._request_hint_for_user(user=user, daily=daily, puzzle=puzzle)
        return PuzzleService._request_hint_for_guest(user=user, daily=daily, puzzle=puzzle)

    @staticmethod
    def get_solution(*, user, level: str | None = None) -> dict:
        level = PuzzleService.normalize_level(level)
        daily = PuzzleService.get_or_create_daily_puzzle(level=level)
        puzzle = daily.puzzle
        state = PuzzleService._get_progress_state(user=user, daily=daily, puzzle=puzzle)
        if getattr(user, "is_authenticated", False) and not getattr(user, "is_guest", False):
            attempt = PuzzleService._get_or_create_attempt(user=user, daily=daily)
            if not attempt.solved:
                attempt.attempts += 1
                attempt.save(update_fields=["attempts"])
        replay_moves, steps = PuzzleService._build_solution_steps(puzzle)
        return {
            "moves": puzzle.moves,
            "replay_moves": replay_moves,
            "steps": steps,
            "solved": bool(state.get("solved", False)),
            "message": "정답 수순을 확인했습니다.",
        }

    @staticmethod
    def get_stats(*, user) -> dict:
        if not getattr(user, "is_authenticated", False) or getattr(user, "is_guest", False):
            return {"total": 0, "solved": 0, "solve_rate": 0.0, "avg_attempts": 0.0}
        cache_key = PuzzleService._user_stats_cache_key(user_id=user.id)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        qs = UserPuzzleAttempt.objects.filter(user=user)
        aggs = qs.aggregate(
            total=Count("id"),
            solved=Count("id", filter=Q(solved=True)),
            avg_attempts=Avg("attempts"),
        )
        total = int(aggs.get("total") or 0)
        solved = int(aggs.get("solved") or 0)
        avg_attempts = float(aggs.get("avg_attempts") or 0.0)
        payload = {
            "total": total,
            "solved": solved,
            "solve_rate": round((solved / total) * 100, 2) if total else 0.0,
            "avg_attempts": round(avg_attempts, 2),
        }
        cache.set(cache_key, payload, PuzzleService.USER_METRICS_CACHE_TTL_SECONDS)
        return payload

    @staticmethod
    def get_streak(*, user) -> dict:
        if not getattr(user, "is_authenticated", False) or getattr(user, "is_guest", False):
            return {"current_streak": 0, "best_streak": 0}
        cache_key = PuzzleService._user_streak_cache_key(user_id=user.id)
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
        solved_dates = list(
            UserPuzzleAttempt.objects.filter(user=user, solved=True)
            .select_related("daily_puzzle")
            .order_by("daily_puzzle__date")
            .values_list("daily_puzzle__date", flat=True)
        )
        if not solved_dates:
            return {"current_streak": 0, "best_streak": 0}

        best = 1
        cur = 1
        for i in range(1, len(solved_dates)):
            if solved_dates[i] == solved_dates[i - 1] + timedelta(days=1):
                cur += 1
                best = max(best, cur)
            elif solved_dates[i] != solved_dates[i - 1]:
                cur = 1

        today = timezone.localdate()
        current = 0
        date_set = set(solved_dates)
        probe = today
        while probe in date_set:
            current += 1
            probe -= timedelta(days=1)
        if current == 0 and (today - timedelta(days=1)) in date_set:
            probe = today - timedelta(days=1)
            while probe in date_set:
                current += 1
                probe -= timedelta(days=1)
        payload = {"current_streak": current, "best_streak": best}
        cache.set(cache_key, payload, PuzzleService.USER_METRICS_CACHE_TTL_SECONDS)
        return payload

    @staticmethod
    def _submit_move_for_user(*, user, daily, puzzle, move_uci: str) -> dict:
        with transaction.atomic():
            attempt = PuzzleService._get_or_create_attempt(user=user, daily=daily, lock=True)
            if attempt.solved:
                return {
                    "correct": True,
                    "completed": True,
                    "already_solved": True,
                    "message": "이미 오늘의 퍼즐을 완료했습니다.",
                }

            result = PuzzleService._evaluate_move(
                puzzle=puzzle, moves_made=attempt.moves_made, move_uci=move_uci
            )
            attempt.attempts += 1
            if result["correct"]:
                attempt.moves_made = result["moves_made"]
                if result["completed"]:
                    attempt.solved = True
                    attempt.solved_at = timezone.now()
            attempt.save(update_fields=["attempts", "moves_made", "solved", "solved_at"])
            PuzzleService._invalidate_user_metrics_cache(user_id=user.id)
            if result["correct"] and result["completed"]:

                def _sync_achievement(user_id=user.id):
                    from apps.accounts.services import AchievementService

                    AchievementService.sync_rewards_for_user(user_id)

                transaction.on_commit(_sync_achievement)
            return result

    @staticmethod
    def _submit_move_for_guest(*, user, daily, puzzle, move_uci: str) -> dict:
        state = PuzzleService._get_guest_state(user=user, daily=daily)
        if state.get("solved"):
            return {
                "correct": True,
                "completed": True,
                "already_solved": True,
                "message": "이미 오늘의 퍼즐을 완료했습니다.",
            }
        result = PuzzleService._evaluate_move(
            puzzle=puzzle, moves_made=state.get("moves_made", []), move_uci=move_uci
        )
        state["attempts"] = int(state.get("attempts", 0)) + 1
        if result["correct"]:
            state["moves_made"] = result["moves_made"]
            if result["completed"]:
                state["solved"] = True
        PuzzleService._set_guest_state(user=user, daily=daily, state=state)
        return result

    @staticmethod
    def _evaluate_move(*, puzzle: Puzzle, moves_made: list, move_uci: str) -> dict:
        next_idx = PuzzleService._expected_user_index(moves_made)
        if next_idx >= len(puzzle.moves):
            return {
                "correct": True,
                "completed": True,
                "moves_made": moves_made,
                "message": "퍼즐을 완료했습니다.",
            }

        expected = puzzle.moves[next_idx]
        board = PuzzleService._build_board_to_index(puzzle=puzzle, index=next_idx)
        try:
            move_obj = chess.Move.from_uci(move_uci)
        except ValueError:
            raise ValidationError({"move": PuzzleService.MSG_INVALID_MOVE_FORMAT}) from None

        if move_obj not in board.legal_moves:
            raise ValidationError({"move": PuzzleService._describe_illegal_move(board, move_obj)})

        if move_uci != expected:
            return {
                "correct": False,
                "completed": False,
                "moves_made": moves_made,
                "hint": None,
                "message": "아쉽지만 정답 수가 아닙니다. 다시 시도해보세요.",
            }

        new_moves_made = list(moves_made) + [move_uci]
        completed = next_idx >= len(puzzle.moves) - 1
        payload = {
            "correct": True,
            "completed": completed,
            "moves_made": new_moves_made,
            "message": "좋아요! 정답 수입니다.",
        }
        if not completed:
            next_auto_idx = next_idx + 1
            if next_auto_idx < len(puzzle.moves):
                payload["next_move"] = puzzle.moves[next_auto_idx]
        else:
            payload["message"] = "축하합니다! 오늘의 퍼즐을 해결했습니다."
        return payload

    @staticmethod
    def _describe_illegal_move(board: chess.Board, move: chess.Move) -> str:
        from_piece = board.piece_at(move.from_square)
        if from_piece is None:
            return "출발 칸에 내 기물이 없습니다. 다른 칸의 기물을 선택해주세요."

        if from_piece.color != board.turn:
            return "지금은 내 차례 기물만 움직일 수 있습니다."

        piece_name = PuzzleService.PIECE_KR.get(from_piece.piece_type, "기물")
        from_sq = chess.square_name(move.from_square).upper()
        to_sq = chess.square_name(move.to_square).upper()
        return (
            f"{piece_name}({from_sq}→{to_sq})는 현재 규칙상 불가능한 이동입니다. "
            "이동 경로와 킹 안전(체크 상태)을 확인해주세요."
        )

    @staticmethod
    def _build_board_to_index(*, puzzle: Puzzle, index: int) -> chess.Board:
        try:
            board = chess.Board(puzzle.fen)
        except ValueError:
            raise ValidationError(PuzzleService.MSG_INVALID_PUZZLE_DATA) from None

        try:
            for uci in puzzle.moves[:index]:
                board.push(chess.Move.from_uci(uci))
        except (ValueError, AssertionError):
            raise ValidationError(PuzzleService.MSG_INVALID_PUZZLE_DATA) from None

        return board

    @staticmethod
    def _expected_user_index(moves_made: list) -> int:
        return 1 + (len(moves_made) * 2)

    @staticmethod
    def _get_or_create_attempt(
        *, user, daily: DailyPuzzle, lock: bool = False
    ) -> UserPuzzleAttempt:
        qs = UserPuzzleAttempt.objects
        if lock:
            qs = qs.select_for_update()
        attempt = qs.filter(user=user, daily_puzzle=daily).first()
        if attempt:
            return attempt
        try:
            return UserPuzzleAttempt.objects.create(
                user=user, daily_puzzle=daily, puzzle=daily.puzzle
            )
        except IntegrityError:
            attempt = qs.filter(user=user, daily_puzzle=daily).first()
            if attempt:
                return attempt
            raise

    @staticmethod
    def _guest_cache_key(*, user, daily: DailyPuzzle) -> str:
        user_id = getattr(user, "id", "anon")
        return f"daily_puzzle_guest:{daily.date.isoformat()}:{user_id}"

    @staticmethod
    def _daily_cache_key(*, level: str, today) -> str:
        return f"daily_puzzle:{today.isoformat()}:{level}"

    @staticmethod
    def _user_stats_cache_key(*, user_id: int) -> str:
        return f"puzzle_stats:{user_id}"

    @staticmethod
    def _user_streak_cache_key(*, user_id: int) -> str:
        return f"puzzle_streak:{user_id}"

    @staticmethod
    def _invalidate_user_metrics_cache(*, user_id: int) -> None:
        cache.delete_many(
            [
                PuzzleService._user_stats_cache_key(user_id=user_id),
                PuzzleService._user_streak_cache_key(user_id=user_id),
            ]
        )

    @staticmethod
    def _get_guest_state(*, user, daily: DailyPuzzle) -> dict:
        return cache.get(PuzzleService._guest_cache_key(user=user, daily=daily), {}) or {}

    @staticmethod
    def _set_guest_state(*, user, daily: DailyPuzzle, state: dict) -> None:
        cache.set(
            PuzzleService._guest_cache_key(user=user, daily=daily),
            state,
            PuzzleService.GUEST_STATE_TTL_SECONDS,
        )

    @staticmethod
    def _get_progress_state(*, user, daily: DailyPuzzle, puzzle: Puzzle) -> dict:
        if getattr(user, "is_authenticated", False) and not getattr(user, "is_guest", False):
            attempt = PuzzleService._get_or_create_attempt(user=user, daily=daily)
            return {
                "solved": attempt.solved,
                "attempts": attempt.attempts,
                "hints_used": attempt.hints_used,
                "moves_made": attempt.moves_made or [],
            }
        state = PuzzleService._get_guest_state(user=user, daily=daily)
        return {
            "solved": bool(state.get("solved", False)),
            "attempts": int(state.get("attempts", 0)),
            "hints_used": int(state.get("hints_used", 0)),
            "moves_made": state.get("moves_made", []) or [],
        }

    @staticmethod
    def _increment_guest_hint(*, user, daily: DailyPuzzle, state: dict) -> int:
        state["hints_used"] = int(state.get("hints_used", 0)) + 1
        PuzzleService._set_guest_state(user=user, daily=daily, state=state)
        return int(state["hints_used"])

    @staticmethod
    def _request_hint_for_user(*, user, daily: DailyPuzzle, puzzle: Puzzle) -> dict:
        with transaction.atomic():
            attempt = PuzzleService._get_or_create_attempt(user=user, daily=daily, lock=True)
            hints_used = int(attempt.hints_used or 0)
            if hints_used >= PuzzleService.HINT_LIMIT:
                return {
                    "hint_type": "limit",
                    "hints_used": hints_used,
                    "remaining_hints": 0,
                    "message": PuzzleService.MSG_HINT_LIMIT_REACHED,
                }

            next_idx = PuzzleService._expected_user_index(attempt.moves_made or [])
            if next_idx >= len(puzzle.moves):
                return {
                    "hint_type": "completed",
                    "hints_used": hints_used,
                    "remaining_hints": max(0, PuzzleService.HINT_LIMIT - hints_used),
                    "message": "이미 오늘의 퍼즐을 완료했습니다.",
                }

            expected = puzzle.moves[next_idx]
            if len(expected) < 4:
                raise ValidationError(PuzzleService.MSG_INVALID_PUZZLE_DATA)

            from_square = expected[:2]
            UserPuzzleAttempt.objects.filter(id=attempt.id).update(hints_used=F("hints_used") + 1)
            attempt.refresh_from_db(fields=["hints_used"])
            used_after = int(attempt.hints_used or 0)
            PuzzleService._invalidate_user_metrics_cache(user_id=user.id)
            return PuzzleService._build_hint_payload(
                puzzle=puzzle,
                expected=expected,
                next_idx=next_idx,
                used_after=used_after,
                from_square=from_square,
            )

    @staticmethod
    def _request_hint_for_guest(*, user, daily: DailyPuzzle, puzzle: Puzzle) -> dict:
        state = PuzzleService._get_progress_state(user=user, daily=daily, puzzle=puzzle)
        hints_used = int(state.get("hints_used", 0))
        if hints_used >= PuzzleService.HINT_LIMIT:
            return {
                "hint_type": "limit",
                "hints_used": hints_used,
                "remaining_hints": 0,
                "message": PuzzleService.MSG_HINT_LIMIT_REACHED,
            }

        next_idx = PuzzleService._expected_user_index(state["moves_made"])
        if next_idx >= len(puzzle.moves):
            return {
                "hint_type": "completed",
                "hints_used": hints_used,
                "remaining_hints": max(0, PuzzleService.HINT_LIMIT - hints_used),
                "message": "이미 오늘의 퍼즐을 완료했습니다.",
            }

        expected = puzzle.moves[next_idx]
        if len(expected) < 4:
            raise ValidationError(PuzzleService.MSG_INVALID_PUZZLE_DATA)

        from_square = expected[:2]
        used_after = PuzzleService._increment_guest_hint(user=user, daily=daily, state=state)
        return PuzzleService._build_hint_payload(
            puzzle=puzzle,
            expected=expected,
            next_idx=next_idx,
            used_after=used_after,
            from_square=from_square,
        )

    @staticmethod
    def _build_hint_payload(
        *, puzzle: Puzzle, expected: str, next_idx: int, used_after: int, from_square: str
    ) -> dict:
        to_square = expected[2:4] if len(expected) >= 4 else ""
        remaining = max(0, PuzzleService.HINT_LIMIT - used_after)
        base = {
            "hints_used": used_after,
            "remaining_hints": remaining,
            "square": from_square,
            "target_square": to_square,
        }
        if used_after == 1:
            return {
                **base,
                "hint_type": "piece",
                "message": f"1단계 힌트: {from_square.upper()} 칸의 말을 먼저 확인하세요.",
            }
        if used_after == 2:
            return {
                **base,
                "hint_type": "target",
                "message": (
                    f"2단계 힌트: {from_square.upper()}의 말을 "
                    f"{to_square.upper()}로 두는 수를 우선 검토해보세요."
                ),
            }

        detail = PuzzleService._build_hint_detail(puzzle=puzzle, next_idx=next_idx)
        return {
            **base,
            "hint_type": "intent",
            "detail": detail,
            "message": f"3단계 힌트: {detail}",
        }

    @staticmethod
    def _build_hint_detail(*, puzzle: Puzzle, next_idx: int) -> str:
        try:
            board = PuzzleService._build_board_to_index(puzzle=puzzle, index=next_idx)
            move = chess.Move.from_uci(puzzle.moves[next_idx])
            return (
                PuzzleService._infer_action_intent(board, move)
                or "강제 수순을 만드는 핵심 수입니다."
            )
        except (ValidationError, ValueError, IndexError):
            return "강제 수순을 만드는 핵심 수입니다."

    @staticmethod
    def serialize_daily_payload(
        *, daily: DailyPuzzle, attempt: UserPuzzleAttempt | None, user
    ) -> dict:
        puzzle = daily.puzzle
        progress = PuzzleService._get_progress_state(user=user, daily=daily, puzzle=puzzle)
        hints_used = int(progress.get("hints_used", 0))
        user_steps_total = max(1, (max(0, len(puzzle.moves) - 1) + 1) // 2)

        attempt_payload = {
            "solved": bool(progress.get("solved", False)),
            "attempts": int(progress.get("attempts", 0)),
            "hints_used": hints_used,
            "moves_made": progress.get("moves_made", []),
        }
        return {
            "date": daily.date.isoformat(),
            "level": daily.level,
            "level_label": PuzzleService.LEVEL_LABELS.get(daily.level, daily.level),
            "puzzle": {
                "id": puzzle.id,
                "fen": puzzle.fen,
                "first_move": puzzle.moves[0] if puzzle.moves else None,
                "rating": puzzle.rating,
                "themes": puzzle.themes,
                "objective": PuzzleService._build_objective(puzzle),
                "user_steps_total": user_steps_total,
            },
            "attempt": attempt_payload,
            "hint_limit": PuzzleService.HINT_LIMIT,
            "hints_used": hints_used,
            "remaining_hints": max(0, PuzzleService.HINT_LIMIT - hints_used),
        }

    @staticmethod
    def _build_solution_steps(puzzle: Puzzle) -> tuple[list[str], list[dict]]:
        if not puzzle.moves:
            return [], []

        board = PuzzleService._build_board_to_index(puzzle=puzzle, index=0)
        replay_moves = []
        steps = []

        for idx, uci in enumerate(puzzle.moves):
            try:
                move = chess.Move.from_uci(uci)
            except ValueError:
                continue

            if move not in board.legal_moves:
                continue

            is_capture = board.is_capture(move)
            moving_piece = board.piece_at(move.from_square)
            san = board.san(move)
            board.push(move)

            # 첫 수는 문제 시작 직전 상태를 맞추는 수라 리플레이 대상에서 제외
            if idx == 0:
                continue

            replay_moves.append(uci)
            turn = "백" if idx % 2 == 1 else "흑"
            piece_name = PuzzleService.PIECE_KR.get(
                moving_piece.piece_type if moving_piece else None,
                "기물",
            )
            to_square = chess.square_name(move.to_square).upper()

            if board.is_checkmate():
                description = f"{turn} {piece_name}으로 체크메이트를 완성합니다."
            elif board.is_check():
                description = f"{turn} {piece_name}으로 체크를 걸어 압박합니다."
            elif move.promotion:
                description = f"{turn} 폰 승격으로 전력을 강화합니다."
            elif is_capture:
                description = f"{turn} {piece_name}으로 상대 기물을 잡습니다."
            else:
                description = f"{turn} {piece_name}을 {to_square}로 전개합니다."

            steps.append(
                {
                    "step": len(steps) + 1,
                    "uci": uci,
                    "san": san,
                    "description": description,
                }
            )

        return replay_moves, steps

    @staticmethod
    def _build_objective(puzzle: Puzzle) -> dict:
        if len(puzzle.moves) < 2:
            return {
                "title": "퍼즐 목표",
                "primary_goal": "최선 수를 찾아 퍼즐을 완료하세요.",
                "move_guide": "",
                "win_condition": "",
                "message": "최선 수를 찾아 퍼즐을 완료하세요.",
            }

        first_user_uci = puzzle.moves[1]
        try:
            board = PuzzleService._build_board_to_index(puzzle=puzzle, index=1)
            move = chess.Move.from_uci(first_user_uci)
            piece = board.piece_at(move.from_square)
            result_board = PuzzleService._build_board_to_index(
                puzzle=puzzle, index=len(puzzle.moves)
            )
        except (ValidationError, ValueError):
            return {
                "title": "퍼즐 목표",
                "primary_goal": "최선 수를 찾아 퍼즐을 완료하세요.",
                "move_guide": "",
                "win_condition": "",
                "message": "최선 수를 찾아 퍼즐을 완료하세요.",
            }

        piece_name = PuzzleService.PIECE_KR.get(piece.piece_type if piece else None, "기물")
        from_square = first_user_uci[:2].upper()
        to_square = first_user_uci[2:4].upper()
        themes = puzzle.themes if isinstance(puzzle.themes, list) else []

        primary_goal = PuzzleService._infer_primary_goal(themes, result_board)
        move_guide = f"첫 수는 {from_square}의 {piece_name}을 {to_square}로 두며 수순을 시작하세요."
        action_intent = PuzzleService._infer_action_intent(board, move)
        followup_plan = PuzzleService._infer_followup_plan(puzzle)
        win_condition = PuzzleService._infer_win_condition(themes, result_board)
        combined = "\n".join(
            x for x in [primary_goal, action_intent, move_guide, followup_plan, win_condition] if x
        ).strip()

        return {
            "title": "퍼즐 목표",
            "primary_goal": primary_goal,
            "action_intent": action_intent,
            "move_guide": move_guide,
            "followup_plan": followup_plan,
            "win_condition": win_condition,
            "from_square": from_square,
            "to_square": to_square,
            "piece": piece_name,
            "message": combined or "최선 수를 찾아 퍼즐을 완료하세요.",
        }

    @staticmethod
    def _infer_primary_goal(themes: list, board: chess.Board) -> str:
        for theme in themes:
            if not isinstance(theme, str):
                continue
            low = theme.lower()
            if low.startswith("matein"):
                turns = low.replace("matein", "")
                if turns.isdigit():
                    return f"목표: {turns}수 내 체크메이트를 완성하세요."
                return "목표: 체크메이트 수순을 완성하세요."
        if board.is_checkmate():
            return "목표: 강제 체크메이트 수순을 완성하세요."
        if board.is_check():
            return "목표: 체크를 유지하며 결정적인 우위를 확보하세요."
        return "목표: 최선 수순으로 기물 우위 또는 킹 안전 우위를 확보하세요."

    @staticmethod
    def _infer_win_condition(themes: list, board: chess.Board) -> str:
        keyword_map = {
            "fork": "전술 포크(양면 공격)를 활용하세요.",
            "pin": "핀 전술로 상대 기물의 움직임을 묶으세요.",
            "skewer": "스큐어 전술로 고가치 기물을 노리세요.",
            "discoveredattack": "발견 공격 전술이 핵심입니다.",
            "sacrifice": "기물 희생으로 강제 수순을 여는 퍼즐입니다.",
            "endgame": "엔드게임 원칙(왕 활성화/폰 진격)을 활용하세요.",
        }
        for theme in themes:
            if not isinstance(theme, str):
                continue
            low = theme.lower()
            if low in keyword_map:
                return f"해설 힌트: {keyword_map[low]}"
        if board.is_checkmate():
            return "성공 조건: 마지막 수에서 상대 킹의 합법 수를 모두 차단해야 합니다."
        return "성공 조건: 정답 수순을 끝까지 정확히 재현하면 클리어됩니다."

    @staticmethod
    def _infer_action_intent(board: chess.Board, move: chess.Move) -> str:
        """첫 수의 전술적 의미를 사람이 이해하기 쉬운 문장으로 변환한다."""
        if move not in board.legal_moves:
            return ""

        moving_piece = board.piece_at(move.from_square)
        piece_name = PuzzleService.PIECE_KR.get(
            moving_piece.piece_type if moving_piece else None, "기물"
        )
        to_square = chess.square_name(move.to_square).upper()
        is_capture = board.is_capture(move)
        board.push(move)
        gives_check = board.is_check()
        board.pop()

        if gives_check and is_capture:
            return f"핵심 의도: {piece_name}으로 {to_square}에서 기물을 잡으며 동시에 체크를 걸어 강제 수를 만듭니다."
        if gives_check:
            return f"핵심 의도: {piece_name}을 {to_square}로 이동해 체크를 걸고 상대 응수를 강제합니다."
        if is_capture:
            return f"핵심 의도: {piece_name}으로 {to_square}의 기물을 획득해 전력 우위를 만듭니다."
        if move.promotion:
            return "핵심 의도: 폰 승격으로 즉시 전력을 강화하고 수순 우위를 만듭니다."
        return f"핵심 의도: {piece_name} 전개로 다음 강제 수(체크/포크/핀)의 발판을 만듭니다."

    @staticmethod
    def _infer_followup_plan(puzzle: Puzzle) -> str:
        """
        퍼즐의 앞부분 수순을 간단 계획으로 보여준다.
        - 플레이어 첫 수(필수)
        - 상대 예상 응수(있으면)
        - 플레이어 마무리 수(있으면)
        """
        if len(puzzle.moves) < 2:
            return ""
        try:
            board = PuzzleService._build_board_to_index(puzzle=puzzle, index=1)
        except ValidationError:
            return ""

        parts = []
        try:
            first = chess.Move.from_uci(puzzle.moves[1])
            if first in board.legal_moves:
                parts.append(f"1) 내 첫 수: {board.san(first)}")
                board.push(first)
        except ValueError:
            return ""

        if len(puzzle.moves) >= 3:
            try:
                opp = chess.Move.from_uci(puzzle.moves[2])
                if opp in board.legal_moves:
                    parts.append(f"2) 상대 응수 예상: {board.san(opp)}")
                    board.push(opp)
            except ValueError:
                pass

        if len(puzzle.moves) >= 4:
            try:
                finish = chess.Move.from_uci(puzzle.moves[3])
                if finish in board.legal_moves:
                    parts.append(f"3) 내 마무리 수: {board.san(finish)}")
            except ValueError:
                pass

        if not parts:
            return ""
        return "진행 방법: " + " → ".join(parts)
