from django.urls import path

from accounts.views.user_views import (
    CurrentUserView,
    LoginView,
    LogoutView,
    ProfileUpdateView,
    SignUpView,
)

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("signup/", SignUpView.as_view(), name="signup"),
    path("me/", CurrentUserView.as_view(), name="current-user"),
    path("profile/", ProfileUpdateView.as_view(), name="profile-update"),
]
