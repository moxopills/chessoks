from .auth_token import AuthToken
from .social_user import SocialUser
from .user import User
from .user_stats import UserStats

# 하위 호환성을 위한 alias (deprecated - 추후 제거 예정)
EmailVerificationToken = AuthToken
PasswordResetToken = AuthToken

__all__ = [
    "User",
    "UserStats",
    "SocialUser",
    "AuthToken",
    # deprecated aliases
    "EmailVerificationToken",
    "PasswordResetToken",
]
