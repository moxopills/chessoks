from django.urls import include, path

from apps.accounts.views.user_views import (
    CurrentUserView,
    EmailVerificationConfirmView,
    EmailVerificationResendView,
    LoginView,
    LogoutView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    ProfileUpdateView,
    SignUpView,
    UserAvatarUpdateView,
)

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("signup/", SignUpView.as_view(), name="signup"),
    path("me/", CurrentUserView.as_view(), name="current-user"),
    path("profile/", ProfileUpdateView.as_view(), name="profile-update"),
    path("profile/avatar/", UserAvatarUpdateView.as_view(), name="avatar-update"),
    path(
        "password-reset/request/", PasswordResetRequestView.as_view(), name="password-reset-request"
    ),
    path(
        "password-reset/confirm/", PasswordResetConfirmView.as_view(), name="password-reset-confirm"
    ),
    path(
        "email-verification/confirm/",
        EmailVerificationConfirmView.as_view(),
        name="email-verification-confirm",
    ),
    path(
        "email-verification/resend/",
        EmailVerificationResendView.as_view(),
        name="email-verification-resend",
    ),
    path("social/", include("apps.accounts.urls.social_urls")),
]
