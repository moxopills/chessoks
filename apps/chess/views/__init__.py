from apps.chess.views.game_views import GameDetailView, GameMoveListView
from apps.chess.views.history_views import GameHistoryView
from apps.chess.views.match_views import CancelMatchView, QuickMatchView
from apps.chess.views.room_views import (
    RoomDetailView,
    RoomJoinView,
    RoomLeaveView,
    RoomListView,
    RoomReadyView,
    RoomStartConfirmView,
)
from apps.chess.views.spectator_views import (
    SpectatorJoinView,
    SpectatorLeaveView,
    SpectatorListView,
)

__all__ = [
    "QuickMatchView",
    "CancelMatchView",
    "GameDetailView",
    "GameMoveListView",
    "GameHistoryView",
    "RoomListView",
    "RoomDetailView",
    "RoomJoinView",
    "RoomLeaveView",
    "RoomReadyView",
    "RoomStartConfirmView",
    "SpectatorListView",
    "SpectatorJoinView",
    "SpectatorLeaveView",
]
