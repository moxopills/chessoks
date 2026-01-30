"""Core 앱 URL 설정"""

from django.urls import path

from apps.core.gcp.views import GCPDirectUploadView, GCPFileDeleteView
from apps.core.health import HealthCheckView, ReadinessCheckView

app_name = "core"

urlpatterns = [
    # 헬스체크
    path("health/", HealthCheckView.as_view(), name="health"),
    path("health/ready/", ReadinessCheckView.as_view(), name="health-ready"),
    # GCP 직접 업로드
    path("gcp/upload/", GCPDirectUploadView.as_view(), name="gcp-upload"),
    # GCP 삭제
    path("gcp/delete/", GCPFileDeleteView.as_view(), name="gcp-delete"),
]
