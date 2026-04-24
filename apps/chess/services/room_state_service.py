from __future__ import annotations


class RoomStateService:
    """방 상태 계산 서비스."""

    @staticmethod
    def is_full(room) -> bool:
        return room.guest is not None

    @classmethod
    def get_player_count(cls, room) -> int:
        return 2 if cls.is_full(room) else 1

    @staticmethod
    def get_spectator_count(room) -> int:
        annotated = getattr(room, "spectator_count_annotated", None)
        if annotated is not None:
            return annotated

        cached = getattr(room, "_spectator_count_cache", None)
        if cached is not None:
            return cached

        count = room.spectators.count()
        room._spectator_count_cache = count
        return count
