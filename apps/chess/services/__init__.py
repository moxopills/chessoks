"""Chess 서비스 lazy export."""

from importlib import import_module

__all__ = [
    "GameService",
    "GameQueryService",
    "AiService",
    "AiMatchService",
    "MatchmakingService",
    "RoomFlowService",
    "RoomQueryService",
    "SpectatorService",
    "RatingService",
    "PuzzleService",
]

_EXPORTS = {
    "GameService": ("apps.chess.services.game_service", "GameService"),
    "GameQueryService": ("apps.chess.services.game_query_service", "GameQueryService"),
    "AiService": ("apps.chess.services.ai_service", "AiService"),
    "AiMatchService": ("apps.chess.services.ai_match_service", "AiMatchService"),
    "MatchmakingService": ("apps.chess.services.matchmaking_service", "MatchmakingService"),
    "RoomFlowService": ("apps.chess.services.room_flow_service", "RoomFlowService"),
    "RoomQueryService": ("apps.chess.services.room_query_service", "RoomQueryService"),
    "SpectatorService": ("apps.chess.services.spectator_service", "SpectatorService"),
    "RatingService": ("apps.chess.services.rating_service", "RatingService"),
    "PuzzleService": ("apps.chess.services.puzzle_service", "PuzzleService"),
}


def __getattr__(name: str):
    try:
        module_path, attr_name = _EXPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}") from exc
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value
