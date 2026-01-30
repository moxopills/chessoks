"""GCS 업로드/삭제 기능 테스트 (mock 기반)"""

from unittest.mock import MagicMock, patch

from django.core.files.uploadedfile import SimpleUploadedFile

import pytest
from rest_framework import status
from rest_framework.exceptions import ValidationError

from apps.core.gcp.uploader import gcp_uploader
from apps.core.gcp.validators import GCPImageValidator


@pytest.fixture
def gcs_client_mock():
    client = MagicMock()
    bucket = MagicMock()
    blob = MagicMock()
    client.bucket.return_value = bucket
    bucket.blob.return_value = blob
    return client, bucket, blob


@pytest.fixture
def image_file():
    png_data = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
        b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    return SimpleUploadedFile("test.png", png_data, content_type="image/png")


@pytest.mark.django_db
class TestGCPValidators:
    def test_validate_file_name_success(self):
        GCPImageValidator.validate_file_name("test.png")
        GCPImageValidator.validate_file_name("my-avatar.jpg")
        GCPImageValidator.validate_file_name("profile_123.webp")

    def test_validate_file_name_fail(self):
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_file_name("")
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_file_name("test")

    def test_validate_extension_success(self):
        for ext in ["jpg", "jpeg", "png", "gif", "webp"]:
            GCPImageValidator.validate_extension(f"test.{ext}", ext)

    def test_validate_extension_fail(self):
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_extension("test.txt", "txt")
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_extension("test.exe", "exe")

        with pytest.raises(ValidationError) as exc_info:
            GCPImageValidator.validate_extension("test.png", "jpg")
        assert "일치하지 않습니다" in str(exc_info.value)

    def test_validate_mime_type_success(self):
        GCPImageValidator.validate_mime_type("png", "image/png")
        GCPImageValidator.validate_mime_type("jpg", "image/jpeg")

    def test_validate_mime_type_fail(self):
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_mime_type("png", "text/plain")

        with pytest.raises(ValidationError) as exc_info:
            GCPImageValidator.validate_mime_type("png", "")
        assert "Content-Type이 필요합니다" in str(exc_info.value)

    def test_validate_file_size_success(self):
        GCPImageValidator.validate_file_size(1024)
        GCPImageValidator.validate_file_size(5 * 1024 * 1024)

    def test_validate_file_size_fail(self):
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_file_size(None)
        with pytest.raises(ValidationError):
            GCPImageValidator.validate_file_size(11 * 1024 * 1024)


@pytest.mark.django_db
class TestGCPUploader:
    @patch("apps.core.gcp.uploader.settings")
    def test_extract_key_from_url(self, mock_settings):
        mock_settings.GCS_BUCKET_NAME = "test-bucket"
        mock_settings.GCS_BASE_URL = "https://storage.googleapis.com/test-bucket/"

        url = "https://storage.googleapis.com/test-bucket/avatars/test.png"
        key = gcp_uploader.extract_key_from_url(url)
        assert key == "avatars/test.png"

    @patch("apps.core.gcp.uploader.settings")
    def test_extract_key_from_invalid_url(self, mock_settings):
        mock_settings.GCS_BUCKET_NAME = "test-bucket"
        mock_settings.GCS_BASE_URL = "https://storage.googleapis.com/test-bucket/"

        assert gcp_uploader.extract_key_from_url("") is None
        assert gcp_uploader.extract_key_from_url("https://example.com/test.png") is None

    @patch("apps.core.gcp.uploader.settings")
    def test_delete_file_success(self, mock_settings, gcs_client_mock):
        client, bucket, blob = gcs_client_mock
        mock_settings.GCS_BUCKET_NAME = "test-bucket"

        blob.exists.return_value = True

        with patch("apps.core.gcp.uploader.GCPUploader.get_client", return_value=client):
            result = gcp_uploader.delete_file("avatars/test.png")
            assert result["message"] == "파일이 성공적으로 삭제되었습니다."
            assert result["key"] == "avatars/test.png"
            blob.delete.assert_called_once()

    @patch("apps.core.gcp.uploader.settings")
    def test_delete_file_not_found(self, mock_settings, gcs_client_mock):
        client, bucket, blob = gcs_client_mock
        mock_settings.GCS_BUCKET_NAME = "test-bucket"

        blob.exists.return_value = False

        with patch("apps.core.gcp.uploader.GCPUploader.get_client", return_value=client):
            with pytest.raises(ValidationError) as exc_info:
                gcp_uploader.delete_file("avatars/nonexistent.png")
            assert "존재하지 않습니다" in str(exc_info.value)

    @patch("apps.core.gcp.uploader.GCPUploader.get_client")
    def test_credentials_error(self, mock_client):
        from google.auth.exceptions import DefaultCredentialsError

        mock_client.side_effect = DefaultCredentialsError()
        with pytest.raises(Exception) as exc_info:
            gcp_uploader.delete_file("test.png")
        assert "자격 증명" in str(exc_info.value)


@pytest.mark.django_db
class TestGCPUploadAPI:
    @patch("apps.core.gcp.uploader.settings")
    def test_upload_image_success(self, mock_settings, authenticated_client, image_file):
        mock_settings.GCS_BUCKET_NAME = "test-bucket"
        mock_settings.GCS_BASE_URL = "https://storage.googleapis.com/test-bucket/"

        with patch("apps.core.gcp.uploader.GCPUploader.upload_fileobj"):
            response = authenticated_client.post(
                "/api/gcp/upload/",
                {"file": image_file, "type": "user_avatar"},
                format="multipart",
            )

            assert response.status_code == status.HTTP_200_OK
            assert "file_url" in response.data
            assert "key" in response.data
            assert "avatars/" in response.data["key"]

    def test_upload_without_auth(self, api_client, image_file):
        response = api_client.post(
            "/api/gcp/upload/", {"file": image_file, "type": "user_avatar"}, format="multipart"
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_upload_without_file(self, authenticated_client):
        response = authenticated_client.post("/api/gcp/upload/", {"type": "user_avatar"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_upload_invalid_file_type(self, authenticated_client):
        txt_file = SimpleUploadedFile("test.txt", b"test", content_type="text/plain")
        response = authenticated_client.post(
            "/api/gcp/upload/", {"file": txt_file, "type": "user_avatar"}, format="multipart"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestGCPDeleteAPI:
    def test_delete_image_success(self, authenticated_client):
        with patch("apps.core.gcp.uploader.GCPUploader.delete_file") as mock_delete:
            mock_delete.return_value = {
                "message": "파일이 성공적으로 삭제되었습니다.",
                "key": "avatars/test.png",
            }
            response = authenticated_client.delete(
                "/api/gcp/delete/", {"key": "avatars/test.png"}, format="json"
            )
            assert response.status_code == status.HTTP_200_OK
            assert response.data["message"] == "파일이 성공적으로 삭제되었습니다."

    def test_delete_without_auth(self, api_client):
        response = api_client.delete("/api/gcp/delete/", {"key": "avatars/test.png"}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_without_key(self, authenticated_client):
        response = authenticated_client.delete("/api/gcp/delete/", {}, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
