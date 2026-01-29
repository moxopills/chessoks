from django.urls import path

from apps.chess.views import (
    CancelMatchView,
    GameDetailView,
    GameHistoryView,
    GameLegalMoveView,
    GameMoveListView,
    QuickMatchView,
    RoomDetailView,
    RoomJoinView,
    RoomLeaveView,
    RoomListView,
    RoomReadyView,
    RoomStartConfirmView,
    SpectatorJoinView,
    SpectatorLeaveView,
    SpectatorListView,
)

app_name = "chess"

urlpatterns = [
    path("quick-match/", QuickMatchView.as_view(), name="quick-match"),
    path("quick-match/cancel/", CancelMatchView.as_view(), name="cancel-match"),
    path("games/<int:game_id>/", GameDetailView.as_view(), name="game-detail"),
    path("games/<int:game_id>/moves/", GameMoveListView.as_view(), name="game-moves"),
    path("games/<int:game_id>/legal-moves/", GameLegalMoveView.as_view(), name="game-legal-moves"),
    path("games/history/", GameHistoryView.as_view(), name="game-history"),
    path("rooms/", RoomListView.as_view(), name="room-list"),
    path("rooms/<int:room_id>/", RoomDetailView.as_view(), name="room-detail"),
    path("rooms/<int:room_id>/join/", RoomJoinView.as_view(), name="room-join"),
    path("rooms/<int:room_id>/leave/", RoomLeaveView.as_view(), name="room-leave"),
    path("rooms/<int:room_id>/ready/", RoomReadyView.as_view(), name="room-ready"),
    path("rooms/<int:room_id>/start/", RoomStartConfirmView.as_view(), name="room-start"),
    path("rooms/<int:room_id>/spectators/", SpectatorListView.as_view(), name="spectator-list"),
    path(
        "rooms/<int:room_id>/spectators/join/", SpectatorJoinView.as_view(), name="spectator-join"
    ),
    path(
        "rooms/<int:room_id>/spectators/leave/",
        SpectatorLeaveView.as_view(),
        name="spectator-leave",
    ),
]
