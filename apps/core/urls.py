"""Core 앱 URL 설정"""

from django.urls import path

from apps.core.S3.views import S3DirectUploadView, S3FileDeleteView

app_name = "core"

urlpatterns = [
    # 직접 업로드
    path("s3/upload/", S3DirectUploadView.as_view(), name="s3-upload"),
    # 삭제
    path("s3/delete/", S3FileDeleteView.as_view(), name="s3-delete"),
]
