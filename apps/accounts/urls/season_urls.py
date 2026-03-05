from django.urls import path

from apps.accounts.views.season_views import (
    CurrentSeasonLeaderboardView,
    CurrentSeasonMeView,
    CurrentSeasonView,
    SeasonDetailView,
    SeasonHistoryView,
    SeasonRewardClaimView,
    SeasonRewardListView,
)

app_name = "seasons"

urlpatterns = [
    path("current/", CurrentSeasonView.as_view(), name="current"),
    path(
        "current/leaderboard/", CurrentSeasonLeaderboardView.as_view(), name="current-leaderboard"
    ),
    path("current/me/", CurrentSeasonMeView.as_view(), name="current-me"),
    path("history/", SeasonHistoryView.as_view(), name="history"),
    path("<int:season_id>/", SeasonDetailView.as_view(), name="detail"),
    path("<int:season_id>/rewards/", SeasonRewardListView.as_view(), name="rewards"),
    path("<int:season_id>/rewards/claim/", SeasonRewardClaimView.as_view(), name="claim"),
]
