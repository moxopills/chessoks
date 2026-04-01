from __future__ import annotations

import logging
import os
import random
from dataclasses import dataclass

from django.core.cache import cache

import chess
import chess.engine
from apps.accounts.models import User
from apps.chess.services.ai_setting_service import AiSettingService


@dataclass(frozen=True)
class AiMoveDecision:
    uci: str
    score: float = 0.0


class AiService:
    logger = logging.getLogger(__name__)
    LEVEL_TO_ROOM_TYPE = {
        "easy": "ai_easy",
        "medium": "ai_medium",
        "hard": "ai_hard",
    }
    ROOM_TYPE_TO_LEVEL = {v: k for k, v in LEVEL_TO_ROOM_TYPE.items()}
    LEVEL_CONFIG = {
        "easy": {"depth": 0, "randomness": 8, "delay_ms": 1200},
        "medium": {"depth": 1, "randomness": 4, "delay_ms": 900},
        "hard": {"depth": 2, "randomness": 2, "delay_ms": 700},
    }
    CACHE_KEY = "ai:level_config:v1"

    PIECE_VALUES = {
        chess.PAWN: 1,
        chess.KNIGHT: 3,
        chess.BISHOP: 3,
        chess.ROOK: 5,
        chess.QUEEN: 9,
    }

    _AI_USER_CACHE: dict[str, User] = {}

    @staticmethod
    def _normalize_level(level: str) -> str:
        return (level or "easy").lower()

    @classmethod
    def get_ai_user(cls, level: str) -> User:
        cached = cls._AI_USER_CACHE.get("single")
        if cached:
            return cached
        email = "ai@chessok.local"
        nickname = "AI"
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "nickname": nickname,
                "is_active": False,
                "email_verified": True,
            },
        )
        if created:
            user.set_unusable_password()
            user.save(update_fields=["password"])
        cls._AI_USER_CACHE["single"] = user
        return user

    @staticmethod
    def choose_move(fen: str, level: str) -> AiMoveDecision | None:
        board = chess.Board(fen)
        moves = list(board.legal_moves)
        if not moves:
            return None

        level = AiService._normalize_level(level)
        config = AiService._get_level_config(level)
        ai_color = board.turn

        # 쉬움 난이도: 간단한 평가 후 랜덤성 높게 선택
        if config["depth"] <= 0:
            return AiService._choose_easy_move(board, moves, config["randomness"])

        if level == "hard":
            stockfish_move = AiService._choose_with_stockfish(board, depth=config["depth"])
            if stockfish_move:
                return stockfish_move

        return AiService._choose_with_eval(
            board,
            moves,
            depth=config["depth"],
            randomness=config["randomness"],
            ai_color=ai_color,
        )

    @classmethod
    def get_delay_ms(cls, level: str) -> int:
        level = cls._normalize_level(level)
        config = cls._get_level_config(level)
        return int(config.get("delay_ms", 0))

    @staticmethod
    def _choose_with_eval(
        board: chess.Board,
        moves: list[chess.Move],
        *,
        depth: int,
        randomness: int,
        ai_color: bool,
    ) -> AiMoveDecision | None:
        """중간/어려움 난이도: minimax 평가 + 랜덤성"""
        ordered_moves = AiService._order_moves(board, moves)
        scored: list[AiMoveDecision] = []

        # randomness에 따른 노이즈 범위 (randomness가 클수록 노이즈도 큼)
        noise_range = randomness * 0.1

        for move in ordered_moves:
            board.push(move)
            if board.is_checkmate():
                board.pop()
                return AiMoveDecision(uci=move.uci(), score=9999.0)
            score = AiService._minimax(board, depth - 1, maximizing=False, ai_color=ai_color)
            board.pop()

            # 작은 랜덤 노이즈 추가 (같은 점수일 때 다양성 확보)
            score += random.uniform(-noise_range, noise_range)
            scored.append(AiMoveDecision(uci=move.uci(), score=score))

        # 먼저 섞어서 동점일 때 다양성 확보
        random.shuffle(scored)
        scored.sort(key=lambda item: item.score, reverse=True)
        return AiService._pick_from_top(scored, randomness)

    @staticmethod
    def _pick_from_top(scored: list[AiMoveDecision], randomness: int) -> AiMoveDecision | None:
        if not scored:
            return None
        top_n = max(1, min(randomness, len(scored)))
        return random.choice(scored[:top_n])

    @staticmethod
    def _choose_easy_move(
        board: chess.Board, moves: list[chess.Move], randomness: int
    ) -> AiMoveDecision:
        """쉬움 난이도: 간단한 휴리스틱으로 점수 매기고 랜덤하게 선택"""
        scored: list[AiMoveDecision] = []

        for move in moves:
            score = random.uniform(0, 5)  # 기본 랜덤 점수

            # 체크메이트는 항상 선택
            board.push(move)
            if board.is_checkmate():
                board.pop()
                return AiMoveDecision(uci=move.uci(), score=100.0)
            board.pop()

            # 캡처에 약간의 가중치
            if board.is_capture(move):
                captured = board.piece_at(move.to_square)
                if captured:
                    score += AiService.PIECE_VALUES.get(captured.piece_type, 1) * 0.5

            # 체크에 약간의 가중치
            if board.gives_check(move):
                score += 1.0

            # 프로모션에 가중치
            if move.promotion:
                score += 3.0

            scored.append(AiMoveDecision(uci=move.uci(), score=score))

        # 점수로 정렬하되 랜덤성이 높아서 다양한 수 선택
        random.shuffle(scored)  # 먼저 섞어서 같은 점수일 때 다양성 확보
        scored.sort(key=lambda item: item.score, reverse=True)

        # randomness 값만큼의 상위 수 중에서 랜덤 선택
        return AiService._pick_from_top(scored, randomness)

    @staticmethod
    def _order_moves(board: chess.Board, moves: list[chess.Move]) -> list[chess.Move]:
        def move_score(move: chess.Move) -> int:
            score = 0
            if board.is_capture(move):
                score += 20
            if board.gives_check(move):
                score += 10
            if move.promotion:
                score += 30
            return score

        return sorted(moves, key=move_score, reverse=True)

    @classmethod
    def _get_level_config(cls, level: str) -> dict[str, int]:
        cached = cache.get(cls.CACHE_KEY)
        if cached:
            return cached.get(level, cls.LEVEL_CONFIG["easy"])
        db_config = AiSettingService.get_config()
        merged = dict(cls.LEVEL_CONFIG)
        for key, value in db_config.items():
            if key in merged:
                merged[key] = {
                    "depth": max(0, int(value.get("depth", merged[key]["depth"]))),
                    "randomness": max(1, int(value.get("randomness", merged[key]["randomness"]))),
                    "delay_ms": max(0, int(value.get("delay_ms", merged[key]["delay_ms"]))),
                }
        cache.set(cls.CACHE_KEY, merged, timeout=60)
        return merged.get(level, cls.LEVEL_CONFIG["easy"])

    @staticmethod
    def _choose_with_stockfish(board: chess.Board, *, depth: int) -> AiMoveDecision | None:
        engine_path = os.getenv("STOCKFISH_PATH")
        if not engine_path:
            return None
        try:
            engine = chess.engine.SimpleEngine.popen_uci(engine_path)
        except Exception:
            AiService.logger.warning("Stockfish engine not available")
            return None
        try:
            limit = chess.engine.Limit(depth=max(1, depth))
            result = engine.play(board, limit)
            if not result.move:
                return None
            return AiMoveDecision(uci=result.move.uci(), score=0.0)
        except Exception:
            AiService.logger.exception("Stockfish evaluation failed")
            return None
        finally:
            try:
                engine.quit()
            except Exception:
                pass

    @staticmethod
    def _minimax(
        board: chess.Board,
        depth: int,
        *,
        maximizing: bool,
        ai_color: bool,
        alpha: float = -9999.0,
        beta: float = 9999.0,
    ) -> float:
        if depth <= 0 or board.is_game_over():
            return AiService._evaluate(board, ai_color)

        moves = list(board.legal_moves)
        if maximizing:
            value = -9999.0
            for move in moves:
                board.push(move)
                value = max(
                    value,
                    AiService._minimax(
                        board,
                        depth - 1,
                        maximizing=False,
                        ai_color=ai_color,
                        alpha=alpha,
                        beta=beta,
                    ),
                )
                board.pop()
                alpha = max(alpha, value)
                if beta <= alpha:
                    break
            return value

        value = 9999.0
        for move in moves:
            board.push(move)
            value = min(
                value,
                AiService._minimax(
                    board,
                    depth - 1,
                    maximizing=True,
                    ai_color=ai_color,
                    alpha=alpha,
                    beta=beta,
                ),
            )
            board.pop()
            beta = min(beta, value)
            if beta <= alpha:
                break
        return value

    @staticmethod
    def _evaluate(board: chess.Board, ai_color: bool) -> float:
        if board.is_checkmate():
            return 9999.0 if board.turn != ai_color else -9999.0
        if board.is_stalemate() or board.is_insufficient_material():
            return 0.0

        score = 0.0
        for piece_type, value in AiService.PIECE_VALUES.items():
            score += len(board.pieces(piece_type, ai_color)) * value
            score -= len(board.pieces(piece_type, not ai_color)) * value
        if board.is_check():
            score += 0.3 if board.turn != ai_color else -0.3
        return score
