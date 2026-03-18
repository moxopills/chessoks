"""Chess 앱 공통 유틸리티"""

import logging
import random
import re

from django.db.models import Count, OuterRef, Subquery

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from korcen import korcen

logger = logging.getLogger(__name__)


def parse_int(value, default: int, min_value: int, max_value: int) -> int:
    """쿼리 파라미터를 정수로 변환 (범위 제한 포함)"""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_value, min(parsed, max_value))


def assign_colors(host, guest):
    """호스트/게스트에게 랜덤으로 흑/백 배정"""
    if random.choice([True, False]):
        return host, guest
    return guest, host


def _serialize_player_summary(user):
    if not user:
        return None

    stats = getattr(user, "stats", None)
    updated_at = getattr(user, "updated_at", None)
    avatar_url = getattr(user, "avatar_url", None)
    if avatar_url and updated_at:
        version = int(updated_at.timestamp())
        separator = "&" if "?" in avatar_url else "?"
        avatar_url = f"{avatar_url}{separator}v={version}"

    return {
        "id": user.id,
        "nickname": user.nickname,
        "avatar_url": avatar_url,
        "rating": getattr(stats, "rating", 1200),
        "rank_tier": getattr(stats, "rank_tier", "Junior"),
        "nickname_color": getattr(stats, "nickname_color", ""),
        "profile_border": getattr(stats, "profile_border", ""),
    }


def _get_room_broadcast_snapshot(room_id: int):
    from apps.chess.models import Game, Room

    playing_game_subquery = (
        Game.objects.filter(room_id=OuterRef("pk"), result="playing")
        .order_by("-created_at")
        .values("id")[:1]
    )

    return (
        Room.objects.select_related(
            "host__stats",
            "guest__stats",
        )
        .annotate(
            current_game_id_annotated=Subquery(playing_game_subquery),
            spectator_count_annotated=Count("spectators", distinct=True),
        )
        .only(
            "id",
            "room_type",
            "title",
            "status",
            "is_private",
            "allow_spectators",
            "time_limit",
            "host_id",
            "host__id",
            "host__nickname",
            "host__avatar_url",
            "host__updated_at",
            "host__stats__rating",
            "host__stats__rank_tier",
            "host__stats__nickname_color",
            "host__stats__profile_border",
            "guest_id",
            "guest__id",
            "guest__nickname",
            "guest__avatar_url",
            "guest__updated_at",
            "guest__stats__rating",
            "guest__stats__rank_tier",
            "guest__stats__nickname_color",
            "guest__stats__profile_border",
            "host_ready",
            "guest_ready",
            "host_start_confirmed",
            "guest_start_confirmed",
        )
        .get(pk=room_id)
    )


def _build_lobby_room_payload(room) -> dict:
    room_snapshot = _get_room_broadcast_snapshot(room.id)
    return {
        "id": room_snapshot.id,
        "room_type": room_snapshot.room_type,
        "title": room_snapshot.title,
        "status": room_snapshot.status,
        "current_game_id": getattr(room_snapshot, "current_game_id_annotated", None),
        "is_private": room_snapshot.is_private,
        "allow_spectators": room_snapshot.allow_spectators,
        "time_limit": room_snapshot.time_limit,
        "host": _serialize_player_summary(room_snapshot.host),
        "guest": _serialize_player_summary(room_snapshot.guest),
        "player_count": 2 if room_snapshot.guest_id else 1,
        "spectator_count": getattr(room_snapshot, "spectator_count_annotated", 0),
    }


def _build_room_state_payload(room) -> dict:
    room_snapshot = _get_room_broadcast_snapshot(room.id)
    return {
        "id": room_snapshot.id,
        "room_type": room_snapshot.room_type,
        "title": room_snapshot.title,
        "status": room_snapshot.status,
        "allow_spectators": room_snapshot.allow_spectators,
        "time_limit": room_snapshot.time_limit,
        "host": _serialize_player_summary(room_snapshot.host),
        "guest": _serialize_player_summary(room_snapshot.guest),
        "host_ready": room_snapshot.host_ready,
        "guest_ready": room_snapshot.guest_ready,
        "host_start_confirmed": room_snapshot.host_start_confirmed,
        "guest_start_confirmed": room_snapshot.guest_start_confirmed,
        "spectator_count": getattr(room_snapshot, "spectator_count_annotated", 0),
    }


def broadcast_room_update(room) -> None:
    """방 업데이트 브로드캐스트"""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_update", "room": _build_lobby_room_payload(room)}
    try:
        async_to_sync(channel_layer.group_send)(
            "chess_lobby", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_room_update failed room=%s: %s", room.id, exc)


def broadcast_room_state(room) -> None:
    """방 대기실/관전용 업데이트 브로드캐스트"""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_update", "room": _build_room_state_payload(room)}
    try:
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room.id}", {"type": "broadcast", "payload": payload}
        )
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room.id}_spectators", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_room_state failed room=%s: %s", room.id, exc)


def broadcast_room_removed(room_id: int) -> None:
    """방 삭제 브로드캐스트"""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    payload = {"type": "room_removed", "room_id": room_id}
    try:
        async_to_sync(channel_layer.group_send)(
            "chess_lobby", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_room_removed failed room_id=%s: %s", room_id, exc)


def broadcast_spectator_event(room_id: int, user, action: str) -> None:
    """관전자 입장/퇴장 이벤트 브로드캐스트"""
    channel_layer = get_channel_layer()
    if channel_layer is None:
        return
    room_snapshot = _get_room_broadcast_snapshot(room_id)
    payload = {
        "type": "spectator_event",
        "action": action,
        "user": _serialize_player_summary(user),
        "spectator_count": getattr(room_snapshot, "spectator_count_annotated", 0),
    }
    try:
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room_id}", {"type": "broadcast", "payload": payload}
        )
        async_to_sync(channel_layer.group_send)(
            f"chess_room_{room_id}_spectators", {"type": "broadcast", "payload": payload}
        )
    except Exception as exc:
        logger.error("broadcast_spectator_event failed room_id=%s: %s", room_id, exc)


_EXTRA_PROFANITY_PATTERNS = re.compile(
    r"(씨발|씨팔|씨바|씨빨|ㅆ발|ㅆ팔|ㅆ바|ㅆㅂ|시발|시팔|시바|시빨|ㅅㅂ|병신|ㅄ|좆|존나|개새끼|새끼|fuck|shit)",
    re.IGNORECASE,
)

# ===== 욕설 필터링 =====


def check_profanity(text: str) -> bool:
    """텍스트에 욕설이 포함되어 있는지 확인"""
    if not text:
        return False
    try:
        if korcen.check(text):
            return True
    except Exception as exc:
        logger.warning("korcen.check failed: %s", exc)
    normalized = re.sub(r"[\s\W_]+", "", text, flags=re.UNICODE)
    return bool(_EXTRA_PROFANITY_PATTERNS.search(normalized))


def filter_profanity(text: str, mask_char: str = "*") -> str:
    """텍스트의 욕설을 마스킹 처리"""
    if not text:
        return text
    return korcen.highlight_profanity(text, highlight_char=mask_char)


def get_profanity_warning() -> str:
    """욕설 감지 시 경고 메시지 반환"""
    return "욕설이 포함된 메시지는 전송할 수 없습니다."
