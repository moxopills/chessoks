from django.urls import include, path

from apps.accounts.views.user_views import (
    AccountDeleteView,
    CurrentUserView,
    EmailChangeConfirmView,
    EmailChangeRequestView,
    EmailCheckView,
    EmailVerificationConfirmView,
    EmailVerificationResendView,
    LoginView,
    LogoutView,
    NicknameCheckView,
    PasswordChangeView,
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
    path("password/change/", PasswordChangeView.as_view(), name="password-change"),
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
    path("account/delete/", AccountDeleteView.as_view(), name="account-delete"),
    path("check-email/", EmailCheckView.as_view(), name="check-email"),
    path("check-nickname/", NicknameCheckView.as_view(), name="check-nickname"),
    path("email/change/", EmailChangeRequestView.as_view(), name="email-change-request"),
    path("email/change/confirm/", EmailChangeConfirmView.as_view(), name="email-change-confirm"),
    path("social/", include("apps.accounts.urls.social_urls")),
]
