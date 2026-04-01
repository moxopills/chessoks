from __future__ import annotations


class MoveNotationService:
    """수 표기 계산 서비스."""

    @staticmethod
    def get_full_move_notation(move) -> str:
        notation = move.san
        if move.is_checkmate:
            return f"{notation}#"
        if move.is_check:
            return f"{notation}+"
        return notation
