from django.urls import path

from apps.chess.views import CancelMatchView, QuickMatchView

app_name = "chess"

urlpatterns = [
    path("quick-match/", QuickMatchView.as_view(), name="quick-match"),
    path("quick-match/cancel/", CancelMatchView.as_view(), name="cancel-match"),
]
