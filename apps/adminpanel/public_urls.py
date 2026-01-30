from django.urls import path

from apps.adminpanel.views import ReportCreateView

app_name = "reports"

urlpatterns = [
    path("", ReportCreateView.as_view(), name="report-create"),
]
