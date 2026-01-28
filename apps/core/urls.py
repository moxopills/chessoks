"""Core 앱 URL 설정"""

from django.urls import path

from apps.core.health import HealthCheckView, ReadinessCheckView
from apps.core.S3.views import S3DirectUploadView, S3FileDeleteView

app_name = "core"

urlpatterns = [
    # 헬스체크
    path("health/", HealthCheckView.as_view(), name="health"),
    path("health/ready/", ReadinessCheckView.as_view(), name="health-ready"),
    # S3 직접 업로드
    path("s3/upload/", S3DirectUploadView.as_view(), name="s3-upload"),
    # S3 삭제
    path("s3/delete/", S3FileDeleteView.as_view(), name="s3-delete"),
]
