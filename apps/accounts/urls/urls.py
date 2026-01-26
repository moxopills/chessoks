from django.urls import include, path

from apps.accounts.views.friend_views import (
    FriendListView,
    FriendRequestAcceptView,
    FriendRequestListCreateView,
    FriendRequestRejectView,
)
from apps.accounts.views.user_views import (
    AccountDeleteView,
    CurrentUserView,
    EmailChangeConfirmView,
    EmailChangeRequestView,
    EmailCheckView,
    EmailVerificationConfirmView,
    EmailVerificationResendView,
    LeaderboardView,
    LoginView,
    LogoutView,
    MyRankView,
    NicknameCheckView,
    OnlineStatusView,
    PasswordChangeView,
    PasswordResetConfirmView,
    PasswordResetRequestView,
    ProfileUpdateView,
    SignUpView,
    UserAvatarUpdateView,
    UserDashboardView,
    UserProfileView,
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
    path("online-status/", OnlineStatusView.as_view(), name="online-status"),
    path("leaderboard/", LeaderboardView.as_view(), name="leaderboard"),
    path("leaderboard/me/", MyRankView.as_view(), name="leaderboard-me"),
    path("dashboard/", UserDashboardView.as_view(), name="dashboard"),
    path("users/<int:user_id>/profile/", UserProfileView.as_view(), name="user-profile"),
    path("friends/", FriendListView.as_view(), name="friends"),
    path("friends/requests/", FriendRequestListCreateView.as_view(), name="friend-requests"),
    path(
        "friends/requests/<int:request_id>/accept/",
        FriendRequestAcceptView.as_view(),
        name="friend-request-accept",
    ),
    path(
        "friends/requests/<int:request_id>/reject/",
        FriendRequestRejectView.as_view(),
        name="friend-request-reject",
    ),
    path("social/", include("apps.accounts.urls.social_urls")),
]
