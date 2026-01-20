from django.urls import path

from apps.chess.consumers import ChessConsumer, LobbyChatConsumer

websocket_urlpatterns = [
    path("ws/lobby/", LobbyChatConsumer.as_asgi()),
    path("ws/chess/<int:room_id>/", ChessConsumer.as_asgi()),
]
