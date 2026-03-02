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
    MSG_NO_PUZZLE_DATA = "현재 사용할 수 있는 퍼즐이 없습니다. 잠시 후 다시 시도해주세요."
    MSG_INVALID_MOVE_FORMAT = "수 입력 형식이 올바르지 않습니다. 예: e2e4"
    MSG_INVALID_PUZZLE_DATA = "퍼즐 데이터가 올바르지 않습니다. 관리자에게 문의해주세요."
    MSG_ILLEGAL_MOVE = "둘 수 없는 수입니다. 말의 이동 규칙을 다시 확인해주세요."
    MSG_HINT_LIMIT_REACHED = "힌트는 하루 최대 3번까지 사용할 수 있습니다."
    MSG_INVALID_LEVEL = "난이도는 쉬움(easy), 중간(medium), 어려움(hard) 중에서 선택해주세요."

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
        daily = DailyPuzzle.objects.select_related("puzzle").filter(date=today, level=level).first()
        if daily:
            return daily
        return PuzzleService.select_daily_puzzle(level=level, today=today)

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
                return DailyPuzzle.objects.create(date=today, level=level, puzzle_id=selected_id)
            except IntegrityError:
                # 레이스 컨디션: 다른 워커가 먼저 생성
                daily = (
                    DailyPuzzle.objects.select_related("puzzle")
                    .filter(date=today, level=level)
                    .first()
                )
                if not daily:
                    raise
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
        return {
            "moves": puzzle.moves,
            "solved": bool(state.get("solved", False)),
            "message": "정답 수순을 확인했습니다.",
        }

    @staticmethod
    def get_stats(*, user) -> dict:
        if not getattr(user, "is_authenticated", False) or getattr(user, "is_guest", False):
            return {"total": 0, "solved": 0, "solve_rate": 0.0, "avg_attempts": 0.0}
        qs = UserPuzzleAttempt.objects.filter(user=user)
        aggs = qs.aggregate(
            total=Count("id"),
            solved=Count("id", filter=Q(solved=True)),
            avg_attempts=Avg("attempts"),
        )
        total = int(aggs.get("total") or 0)
        solved = int(aggs.get("solved") or 0)
        avg_attempts = float(aggs.get("avg_attempts") or 0.0)
        return {
            "total": total,
            "solved": solved,
            "solve_rate": round((solved / total) * 100, 2) if total else 0.0,
            "avg_attempts": round(avg_attempts, 2),
        }

    @staticmethod
    def get_streak(*, user) -> dict:
        if not getattr(user, "is_authenticated", False) or getattr(user, "is_guest", False):
            return {"current_streak": 0, "best_streak": 0}
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
        return {"current_streak": current, "best_streak": best}

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
            raise ValidationError({"move": PuzzleService.MSG_ILLEGAL_MOVE})

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
            return {
                "hint_type": "piece",
                "square": from_square,
                "hints_used": used_after,
                "remaining_hints": max(0, PuzzleService.HINT_LIMIT - used_after),
                "message": f"힌트 {used_after}/{PuzzleService.HINT_LIMIT} 사용",
            }

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
        return {
            "hint_type": "piece",
            "square": from_square,
            "hints_used": used_after,
            "remaining_hints": max(0, PuzzleService.HINT_LIMIT - used_after),
            "message": f"힌트 {used_after}/{PuzzleService.HINT_LIMIT} 사용",
        }

    @staticmethod
    def serialize_daily_payload(
        *, daily: DailyPuzzle, attempt: UserPuzzleAttempt | None, user
    ) -> dict:
        puzzle = daily.puzzle
        hints_used = 0
        if attempt:
            hints_used = int(attempt.hints_used or 0)
        elif getattr(user, "is_authenticated", False) and getattr(user, "is_guest", False):
            guest_state = PuzzleService._get_guest_state(user=user, daily=daily)
            hints_used = int(guest_state.get("hints_used", 0))

        attempt_payload = None
        if attempt:
            attempt_payload = {
                "solved": attempt.solved,
                "attempts": attempt.attempts,
                "hints_used": attempt.hints_used,
                "moves_made": attempt.moves_made,
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
            },
            "attempt": attempt_payload,
            "hint_limit": PuzzleService.HINT_LIMIT,
            "hints_used": hints_used,
            "remaining_hints": max(0, PuzzleService.HINT_LIMIT - hints_used),
        }
