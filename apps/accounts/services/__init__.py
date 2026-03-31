from importlib import import_module

__all__ = [
    "SocialAuthService",
    "AchievementService",
    "AuthService",
    "AccountService",
    "PasswordService",
    "ServiceResult",
    "AccountSessionService",
    "UserProfileService",
    "ProfileViewService",
    "RankingService",
    "SeasonService",
    "SkinService",
    "OnlineStatusService",
    "PresenceService",
    "FriendService",
    "MessageService",
]

_EXPORTS = {
    "SocialAuthService": ("apps.accounts.services.social_service", "SocialAuthService"),
    "AchievementService": ("apps.accounts.services.achievement_service", "AchievementService"),
    "AuthService": ("apps.accounts.services.session_service", "AuthService"),
    "AccountService": ("apps.accounts.services.session_service", "AccountService"),
    "PasswordService": ("apps.accounts.services.session_service", "PasswordService"),
    "AccountSessionService": ("apps.accounts.services.session_service", "AccountSessionService"),
    "ServiceResult": ("apps.accounts.services.base_service", "ServiceResult"),
    "UserProfileService": ("apps.accounts.services.profile_service", "UserProfileService"),
    "ProfileViewService": ("apps.accounts.services.profile_view_service", "ProfileViewService"),
    "RankingService": ("apps.accounts.services.ranking_service", "RankingService"),
    "SeasonService": ("apps.accounts.services.season_service", "SeasonService"),
    "SkinService": ("apps.accounts.services.skin_service", "SkinService"),
    "OnlineStatusService": (
        "apps.accounts.services.online_status_service",
        "OnlineStatusService",
    ),
    "PresenceService": ("apps.accounts.services.presence_service", "PresenceService"),
    "FriendService": ("apps.accounts.services.friend_service", "FriendService"),
    "MessageService": ("apps.accounts.services.message_service", "MessageService"),
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
