"""소셜 로그인 URL"""

from django.urls import path

from accounts.views.social_views import (
    SocialAccountListView,
    SocialAccountUnlinkView,
    SocialLoginView,
)

app_name = "social"

urlpatterns = [
    path("login/", SocialLoginView.as_view(), name="social-login"),
    path("accounts/", SocialAccountListView.as_view(), name="social-accounts"),
    path("accounts/unlink/", SocialAccountUnlinkView.as_view(), name="social-unlink"),
]
