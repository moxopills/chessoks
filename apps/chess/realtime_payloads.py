"""실시간 Consumer용 공통 payload 헬퍼."""

from __future__ import annotations

from django.utils import timezone

from apps.accounts.services.achievement_service import AchievementService
from apps.accounts.services.presence_service import PresenceService
from apps.accounts.services.user_stats_service import UserStatsService

REACTION_EMOJIS: tuple[str, ...] = ("👍", "👏")


def empty_reactions() -> dict[str, int]:
    return dict.fromkeys(REACTION_EMOJIS, 0)


def build_chat_payload(
    *,
    scope: str,
    user,
    message,
    message_id,
    room_id: int | None = None,
    sent_at=None,
    reactions: dict[str, int] | None = None,
    my_reactions: list[str] | None = None,
) -> dict:
    payload = {
        "type": "chat",
        "scope": scope,
        "message_id": message_id,
        "user_id": user.id,
        "nickname": user.nickname,
        "avatar_url": user.avatar_url,
        "message": message,
        "sent_at": (sent_at or timezone.now()).isoformat(),
        "reactions": reactions or empty_reactions(),
        "my_reactions": my_reactions or [],
    }
    if room_id is not None:
        payload["room_id"] = room_id
    return payload


def build_lobby_user_payload(user, *, presence: dict | None = None) -> dict:
    status = presence or {}
    stats = getattr(user, "stats", None)
    return {
        "id": user.id,
        "nickname": user.nickname,
        "avatar_url": user.avatar_url,
        "rank_tier": UserStatsService.get_rank_tier(stats),
        "nickname_color": getattr(stats, "nickname_color", ""),
        "profile_border": getattr(stats, "profile_border", ""),
        "status": status.get("status", PresenceService.STATUS_ONLINE),
        "status_label": status.get("status_label", "온라인"),
        "featured_achievement": AchievementService.get_featured_achievement_for_stats(stats),
    }


def build_guest_lobby_payload(guest: dict) -> dict:
    return {
        "id": f"guest_{guest['token'][:8]}",
        "nickname": guest["display_name"],
        "avatar_url": None,
        "rank_tier": None,
        "is_guest": True,
    }
