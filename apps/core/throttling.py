"""보안 민감 액션 전용 DRF throttle 모음."""

from rest_framework.throttling import ScopedRateThrottle


class AuthLoginThrottle(ScopedRateThrottle):
    scope = "auth_login"


class AuthSignupThrottle(ScopedRateThrottle):
    scope = "auth_signup"


class AuthVerificationThrottle(ScopedRateThrottle):
    scope = "auth_verify"


class AuthPasswordResetThrottle(ScopedRateThrottle):
    scope = "auth_password_reset"


class AvatarUploadThrottle(ScopedRateThrottle):
    scope = "auth_avatar_upload"


class FriendActionThrottle(ScopedRateThrottle):
    scope = "friend_action"


class InviteActionThrottle(ScopedRateThrottle):
    scope = "invite_action"


class ReportActionThrottle(ScopedRateThrottle):
    scope = "report_action"


class MessageActionThrottle(ScopedRateThrottle):
    scope = "message_action"


class SkinActionThrottle(ScopedRateThrottle):
    scope = "skin_action"


class SocialAuthThrottle(ScopedRateThrottle):
    scope = "social_auth"
