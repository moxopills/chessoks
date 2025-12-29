from django.urls import include, path

from accounts.views.password_views import (
    PasswordResetConfirmView,
    PasswordResetRequestView,
)
from accounts.views.user_views import (
    CurrentUserView,
    LoginView,
    LogoutView,
    ProfileUpdateView,
    SignUpView,
)

app_name = "accounts"

urlpatterns = [
    # 일반 인증
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("signup/", SignUpView.as_view(), name="signup"),
    path("me/", CurrentUserView.as_view(), name="current-user"),
    path("profile/", ProfileUpdateView.as_view(), name="profile-update"),
    # 비밀번호 재설정
    path(
        "password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"
    ),
    path(
        "password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"
    ),
    # 소셜 인증
    path("social/", include("accounts.urls.social_urls")),
]
