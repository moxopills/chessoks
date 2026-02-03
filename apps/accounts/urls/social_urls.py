"""소셜 로그인 URL"""

from django.urls import path

from apps.accounts.views.social_views import (
    SocialAccountListView,
    SocialAccountUnlinkView,
    SocialOAuthCallbackView,
    SocialOAuthStartView,
)

app_name = "social"

urlpatterns = [
    path("<str:provider>/login/", SocialOAuthStartView.as_view(), name="oauth-start"),
    path("<str:provider>/callback/", SocialOAuthCallbackView.as_view(), name="oauth-callback"),
    path("accounts/", SocialAccountListView.as_view(), name="social-accounts"),
    path("accounts/unlink/", SocialAccountUnlinkView.as_view(), name="social-unlink"),
]
