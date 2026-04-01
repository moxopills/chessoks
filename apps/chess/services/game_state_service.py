from __future__ import annotations

from apps.chess.models import Game


class GameStateService:
    """게임 상태 계산 서비스."""

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
    def is_finished(game: Game) -> bool:
        return game.result != Game.Status.PLAYING

    @classmethod
    def get_winner(cls, game: Game):
        if game.result in cls.WHITE_WIN_RESULTS:
            return game.white_player
        if game.result in cls.BLACK_WIN_RESULTS:
            return game.black_player
        return None
