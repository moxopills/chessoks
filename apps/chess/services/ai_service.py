from __future__ import annotations

import logging
import os
import random
from dataclasses import dataclass

from django.core.cache import cache

import chess
import chess.engine
from apps.accounts.models import User
from apps.chess.models import AiDifficultySetting


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
        "easy": {"depth": 0, "randomness": 8},
        "medium": {"depth": 1, "randomness": 4},
        "hard": {"depth": 2, "randomness": 2},
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
        level = cls._normalize_level(level)
        cached = cls._AI_USER_CACHE.get(level)
        if cached:
            return cached
        email = f"ai_{level}@chessok.local"
        nickname = f"AI-{level}"
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
        cls._AI_USER_CACHE[level] = user
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
        if config["depth"] <= 0:
            move = random.choice(moves)
            return AiMoveDecision(uci=move.uci(), score=0.0)

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

    @staticmethod
    def _choose_with_eval(
        board: chess.Board,
        moves: list[chess.Move],
        *,
        depth: int,
        randomness: int,
        ai_color: bool,
    ) -> AiMoveDecision | None:
        ordered_moves = AiService._order_moves(board, moves)
        scored: list[AiMoveDecision] = []
        for move in ordered_moves:
            board.push(move)
            if board.is_checkmate():
                board.pop()
                return AiMoveDecision(uci=move.uci(), score=9999.0)
            score = AiService._minimax(board, depth - 1, maximizing=False, ai_color=ai_color)
            board.pop()
            scored.append(AiMoveDecision(uci=move.uci(), score=score))

        scored.sort(key=lambda item: item.score, reverse=True)
        return AiService._pick_from_top(scored, randomness)

    @staticmethod
    def _pick_from_top(scored: list[AiMoveDecision], randomness: int) -> AiMoveDecision | None:
        if not scored:
            return None
        top_n = max(1, min(randomness, len(scored)))
        return random.choice(scored[:top_n])

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
        db_config = AiDifficultySetting.get_config()
        merged = dict(cls.LEVEL_CONFIG)
        for key, value in db_config.items():
            if key in merged:
                merged[key] = {
                    "depth": max(0, int(value.get("depth", merged[key]["depth"]))),
                    "randomness": max(1, int(value.get("randomness", merged[key]["randomness"]))),
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
