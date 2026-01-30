from django.urls import path

from apps.adminpanel.views import (
    AdminDashboardView,
    AdminReportListView,
    AdminReportResolveView,
    AdminStatsView,
    AdminUserForceDeleteView,
    AdminUserListView,
    AdminUserMuteView,
    AdminUserPromoteView,
    AdminUserSuspendView,
    AdminUserUnmuteView,
    AdminUserUnsuspendView,
)

app_name = "adminpanel"

urlpatterns = [
    path("panel/", AdminDashboardView.as_view(), name="dashboard"),
    path("stats/", AdminStatsView.as_view(), name="stats"),
    path("users/", AdminUserListView.as_view(), name="users"),
    path("users/<int:user_id>/promote/", AdminUserPromoteView.as_view(), name="promote"),
    path("users/<int:user_id>/suspend/", AdminUserSuspendView.as_view(), name="suspend"),
    path("users/<int:user_id>/unsuspend/", AdminUserUnsuspendView.as_view(), name="unsuspend"),
    path("users/<int:user_id>/mute/", AdminUserMuteView.as_view(), name="mute"),
    path("users/<int:user_id>/unmute/", AdminUserUnmuteView.as_view(), name="unmute"),
    path(
        "users/<int:user_id>/force-delete/", AdminUserForceDeleteView.as_view(), name="force-delete"
    ),
    path("reports/", AdminReportListView.as_view(), name="reports"),
    path(
        "reports/<int:report_id>/resolve/", AdminReportResolveView.as_view(), name="report-resolve"
    ),
]
