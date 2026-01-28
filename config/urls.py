"""
URL configuration for config project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/6.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path
from django.views.generic import TemplateView

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    # Admin
    path("admin/", admin.site.urls),
    # API endpoints
    path("api/accounts/", include("apps.accounts.urls")),
    path("api/chess/", include("apps.chess.urls")),
    path("api/notifications/", include("apps.notifications.urls")),
    path("api/", include("apps.core.urls")),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    # Frontend pages
    path("", TemplateView.as_view(template_name="chess/lobby.html"), name="home"),
    path("login/", TemplateView.as_view(template_name="accounts/login.html"), name="login"),
    path("signup/", TemplateView.as_view(template_name="accounts/signup.html"), name="signup"),
    path(
        "password-reset/",
        TemplateView.as_view(template_name="accounts/password_reset.html"),
        name="password-reset",
    ),
    path("profile/", TemplateView.as_view(template_name="accounts/profile.html"), name="profile"),
    path("rooms/", TemplateView.as_view(template_name="chess/room_list.html"), name="room-list"),
    path(
        "rooms/<int:room_id>/",
        TemplateView.as_view(template_name="chess/room_waiting.html"),
        name="room-detail",
    ),
    path(
        "games/<int:room_id>/", TemplateView.as_view(template_name="chess/game.html"), name="game"
    ),
    path(
        "leaderboard/",
        TemplateView.as_view(template_name="social/leaderboard.html"),
        name="leaderboard",
    ),
    path("friends/", TemplateView.as_view(template_name="social/friends.html"), name="friends"),
    path(
        "history/",
        TemplateView.as_view(template_name="chess/game_history.html"),
        name="game-history",
    ),
    path(
        "users/<int:user_id>/",
        TemplateView.as_view(template_name="accounts/user_profile.html"),
        name="user-profile",
    ),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
