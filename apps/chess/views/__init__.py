from apps.chess.views.game_views import (
    GameCapturedView,
    GameDetailView,
    GameLegalMoveView,
    GameMoveListView,
    GameRematchView,
)
from apps.chess.views.history_views import GameHistoryView
from apps.chess.views.invite_views import (
    GameInviteAcceptView,
    GameInviteDeclineView,
    GameInviteView,
)
from apps.chess.views.match_views import (
    AiMatchView,
    CancelMatchView,
    CancelRandomMatchView,
    QuickMatchView,
    RandomMatchView,
)
from apps.chess.views.room_views import (
    RoomActiveView,
    RoomDetailView,
    RoomJoinView,
    RoomLeaveView,
    RoomListView,
    RoomReadyView,
    RoomStartConfirmView,
    RoomWaitingView,
)
from apps.chess.views.spectator_views import (
    SpectatorJoinView,
    SpectatorLeaveView,
    SpectatorListView,
)

__all__ = [
    "QuickMatchView",
    "AiMatchView",
    "CancelMatchView",
    "RandomMatchView",
    "CancelRandomMatchView",
    "GameDetailView",
    "GameCapturedView",
    "GameLegalMoveView",
    "GameMoveListView",
    "GameRematchView",
    "GameHistoryView",
    "GameInviteView",
    "GameInviteAcceptView",
    "GameInviteDeclineView",
    "RoomListView",
    "RoomDetailView",
    "RoomActiveView",
    "RoomJoinView",
    "RoomLeaveView",
    "RoomReadyView",
    "RoomStartConfirmView",
    "RoomWaitingView",
    "SpectatorListView",
    "SpectatorJoinView",
    "SpectatorLeaveView",
]
