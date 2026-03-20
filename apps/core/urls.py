"""Core 앱 URL 설정"""

from django.urls import path

from apps.core.gcp.views import GCPDirectUploadView, GCPFileDeleteView
from apps.core.health import (
    DetailedHealthCheckView,
    HealthCheckView,
    ReadinessCheckView,
    RuntimeMetricsView,
)

app_name = "core"

urlpatterns = [
    # 헬스체크
    path("health/", HealthCheckView.as_view(), name="health"),
    path("health/ready/", ReadinessCheckView.as_view(), name="health-ready"),
    path("health/details/", DetailedHealthCheckView.as_view(), name="health-details"),
    path("health/metrics/", RuntimeMetricsView.as_view(), name="health-metrics"),
    # GCP 직접 업로드
    path("gcp/upload/", GCPDirectUploadView.as_view(), name="gcp-upload"),
    # GCP 삭제
    path("gcp/delete/", GCPFileDeleteView.as_view(), name="gcp-delete"),
]
