from django.urls import path

from apps.chess.consumers import ChessConsumer

websocket_urlpatterns = [
    path("ws/chess/<int:room_id>/", ChessConsumer.as_asgi()),
]
