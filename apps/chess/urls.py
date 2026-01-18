from django.urls import path

from apps.chess.views import QuickMatchView

app_name = "chess"

urlpatterns = [
    path("quick-match/", QuickMatchView.as_view(), name="quick-match"),
]
