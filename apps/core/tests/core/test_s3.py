"""S3 기능 테스트 (moto 사용)"""

from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile

import pytest
from moto import mock_aws
from rest_framework import status
from rest_framework.exceptions import ValidationError

from apps.core.S3.uploader import s3_uploader
from apps.core.S3.validators import S3ImageValidator


@pytest.fixture
def s3_mock():
    """S3 Mock 설정"""
    with mock_aws():
        import boto3

        s3_client = boto3.client(
            "s3",
            region_name="ap-northeast-2",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
        s3_client.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": "ap-northeast-2"},
        )
        yield s3_client


@pytest.fixture
def image_file():
    """테스트용 이미지 파일"""
    png_data = (
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01"
        b"\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
    )
    return SimpleUploadedFile("test.png", png_data, content_type="image/png")


@pytest.mark.django_db
class TestS3Validators:
    """S3 검증 테스트"""

    def test_validate_file_name_success(self):
        """파일명 검증 - 성공"""
        S3ImageValidator.validate_file_name("test.png")
        S3ImageValidator.validate_file_name("my-avatar.jpg")
        S3ImageValidator.validate_file_name("profile_123.webp")

    def test_validate_file_name_fail(self):
        """파일명 검증 - 실패"""
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_file_name("")
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_file_name("test")  # 확장자 없음

    def test_validate_extension_success(self):
        """확장자 검증 - 성공"""
        for ext in ["jpg", "jpeg", "png", "gif", "webp"]:
            S3ImageValidator.validate_extension(f"test.{ext}", ext)

    def test_validate_extension_fail(self):
        """확장자 검증 - 실패"""
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_extension("test.txt", "txt")
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_extension("test.exe", "exe")

        with pytest.raises(ValidationError) as exc_info:
            S3ImageValidator.validate_extension("test.png", "jpg")
        assert "일치하지 않습니다" in str(exc_info.value)

    def test_validate_mime_type_success(self):
        """MIME 타입 검증 - 성공"""
        S3ImageValidator.validate_mime_type("png", "image/png")
        S3ImageValidator.validate_mime_type("jpg", "image/jpeg")

    def test_validate_mime_type_fail(self):
        """MIME 타입 검증 - 실패"""
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_mime_type("png", "text/plain")

        with pytest.raises(ValidationError) as exc_info:
            S3ImageValidator.validate_mime_type("png", "")
        assert "Content-Type이 필요합니다" in str(exc_info.value)

    def test_validate_file_size_success(self):
        """파일 크기 검증 - 성공"""
        S3ImageValidator.validate_file_size(1024)
        S3ImageValidator.validate_file_size(5 * 1024 * 1024)

    def test_validate_file_size_fail(self):
        """파일 크기 검증 - 실패"""
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_file_size(None)
        with pytest.raises(ValidationError):
            S3ImageValidator.validate_file_size(11 * 1024 * 1024)

@pytest.mark.django_db
class TestS3Uploader:
    """S3 업로더 테스트"""

    @patch("apps.core.S3.uploader.settings")
    def test_extract_key_from_url(self, mock_settings):
        """URL에서 키 추출 테스트"""
        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        url = "https://test-bucket.s3.ap-northeast-2.amazonaws.com/avatars/test.png"
        key = s3_uploader.extract_key_from_url(url)
        assert key == "avatars/test.png"

    @patch("apps.core.S3.uploader.settings")
    def test_extract_key_from_invalid_url(self, mock_settings):
        """잘못된 URL에서 키 추출 - None 반환"""
        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        assert s3_uploader.extract_key_from_url("") is None
        assert s3_uploader.extract_key_from_url("https://example.com/test.png") is None

    @patch("apps.core.S3.uploader.settings")
    def test_delete_file_success(self, mock_settings, s3_mock):
        """파일 삭제 - 성공"""
        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"
        mock_settings.AWS_S3_ACCESS_KEY_ID = "test"
        mock_settings.AWS_S3_SECRET_ACCESS_KEY = "test"

        # 파일 생성
        key = "avatars/test.png"
        s3_mock.put_object(Bucket="test-bucket", Key=key, Body=b"test")

        # 삭제
        with patch("apps.core.S3.uploader.s3_uploader.get_s3_client", return_value=s3_mock):
            result = s3_uploader.delete_file(key)
            assert result["message"] == "파일이 성공적으로 삭제되었습니다."
            assert result["key"] == key

    @patch("apps.core.S3.uploader.settings")
    def test_delete_file_not_found(self, mock_settings, s3_mock):
        """파일 삭제 - 파일 없음 (404)"""

        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"
        mock_settings.AWS_S3_ACCESS_KEY_ID = "test"
        mock_settings.AWS_S3_SECRET_ACCESS_KEY = "test"

        key = "avatars/nonexistent.png"

        with patch("apps.core.S3.uploader.s3_uploader.get_s3_client", return_value=s3_mock):
            with pytest.raises(Exception) as exc_info:
                s3_uploader.delete_file(key)
            assert "존재하지 않습니다" in str(exc_info.value)

    @patch("apps.core.S3.uploader.settings")
    @patch("apps.core.S3.uploader.s3_uploader.get_s3_client")
    def test_s3_credentials_error(self, mock_client, mock_settings):
        """S3 자격 증명 오류"""
        from unittest.mock import MagicMock

        from botocore.exceptions import NoCredentialsError

        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        # NoCredentialsError 발생시키기
        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = NoCredentialsError()
        mock_client.return_value = mock_s3

        with pytest.raises(Exception) as exc_info:
            s3_uploader.delete_file("test.png")
        # NoCredentialsError는 ClientError로 변환되어 처리됨
        assert "오류가 발생했습니다" in str(exc_info.value)

    @patch("apps.core.S3.uploader.settings")
    @patch("apps.core.S3.uploader.s3_uploader.get_s3_client")
    def test_s3_client_error(self, mock_client, mock_settings):
        """S3 ClientError"""
        from unittest.mock import MagicMock

        from botocore.exceptions import ClientError

        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        # ClientError 발생시키기
        mock_s3 = MagicMock()
        error_response = {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}
        mock_s3.head_object.side_effect = ClientError(error_response, "HeadObject")
        mock_client.return_value = mock_s3

        with pytest.raises(Exception) as exc_info:
            s3_uploader.delete_file("test.png")
        assert "오류가 발생했습니다" in str(exc_info.value)

    @patch("apps.core.S3.uploader.settings")
    @patch("apps.core.S3.uploader.s3_uploader.get_s3_client")
    def test_s3_param_validation_error(self, mock_client, mock_settings):
        """S3 파라미터 검증 오류"""
        from unittest.mock import MagicMock

        from botocore.exceptions import ParamValidationError

        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        # ParamValidationError 발생시키기
        mock_s3 = MagicMock()
        param_error = ParamValidationError(report="Invalid parameter")
        mock_s3.head_object.side_effect = param_error
        mock_client.return_value = mock_s3

        with pytest.raises(Exception) as exc_info:
            s3_uploader.delete_file("test.png")
        # 모든 boto 예외는 최종적으로 APIException으로 변환됨
        assert "오류가 발생했습니다" in str(exc_info.value)

    @patch("apps.core.S3.uploader.settings")
    @patch("apps.core.S3.uploader.s3_uploader.get_s3_client")
    def test_s3_botocore_error(self, mock_client, mock_settings):
        """S3 BotoCore 오류"""
        from unittest.mock import MagicMock

        from botocore.exceptions import BotoCoreError

        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        # BotoCoreError 발생시키기
        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = BotoCoreError()
        mock_client.return_value = mock_s3

        with pytest.raises(Exception) as exc_info:
            s3_uploader.delete_file("test.png")
        # 모든 boto 예외는 최종적으로 APIException으로 변환됨
        assert "오류가 발생했습니다" in str(exc_info.value)

    @patch("apps.core.S3.uploader.settings")
    @patch("apps.core.S3.uploader.s3_uploader.get_s3_client")
    def test_s3_unexpected_error(self, mock_client, mock_settings):
        """S3 예상치 못한 오류"""
        from unittest.mock import MagicMock

        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"

        # 일반 Exception 발생시키기
        mock_s3 = MagicMock()
        mock_s3.head_object.side_effect = RuntimeError("Unexpected error")
        mock_client.return_value = mock_s3

        with pytest.raises(Exception) as exc_info:
            s3_uploader.delete_file("test.png")
        # 모든 boto 예외는 최종적으로 APIException으로 변환됨
        assert "오류가 발생했습니다" in str(exc_info.value)


@pytest.mark.django_db
class TestS3UploadAPI:
    """S3 업로드 API 테스트"""

    @patch("apps.core.S3.uploader.settings")
    def test_upload_image_success(self, mock_settings, authenticated_client, image_file, s3_mock):
        """이미지 업로드 - 성공"""
        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"
        mock_settings.AWS_S3_ACCESS_KEY_ID = "test"
        mock_settings.AWS_S3_SECRET_ACCESS_KEY = "test"

        with patch("apps.core.S3.uploader.s3_uploader.get_s3_client", return_value=s3_mock):
            response = authenticated_client.post(
                "/api/s3/upload/",
                {"file": image_file, "type": "user_avatar"},
                format="multipart",
            )

            assert response.status_code == status.HTTP_200_OK
            assert "file_url" in response.data
            assert "key" in response.data
            assert "avatars/" in response.data["key"]

    def test_upload_without_auth(self, api_client, image_file):
        """인증 없이 업로드 - 실패"""
        response = api_client.post(
            "/api/s3/upload/", {"file": image_file, "type": "user_avatar"}, format="multipart"
        )
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_upload_without_file(self, authenticated_client):
        """파일 없이 업로드 - 실패"""
        response = authenticated_client.post("/api/s3/upload/", {"type": "user_avatar"})
        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_upload_invalid_file_type(self, authenticated_client):
        """잘못된 파일 타입 - 실패"""
        txt_file = SimpleUploadedFile("test.txt", b"test", content_type="text/plain")
        response = authenticated_client.post(
            "/api/s3/upload/", {"file": txt_file, "type": "user_avatar"}, format="multipart"
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.django_db
class TestS3DeleteAPI:
    """S3 삭제 API 테스트"""

    @patch("apps.core.S3.uploader.settings")
    def test_delete_image_success(self, mock_settings, authenticated_client, s3_mock):
        """이미지 삭제 - 성공"""
        mock_settings.AWS_S3_BUCKET_NAME = "test-bucket"
        mock_settings.AWS_S3_REGION = "ap-northeast-2"
        mock_settings.AWS_S3_ACCESS_KEY_ID = "test"
        mock_settings.AWS_S3_SECRET_ACCESS_KEY = "test"

        # 파일 생성
        key = "avatars/test.png"
        s3_mock.put_object(Bucket="test-bucket", Key=key, Body=b"test")

        with patch("apps.core.S3.uploader.s3_uploader.get_s3_client", return_value=s3_mock):
            response = authenticated_client.delete("/api/s3/delete/", {"key": key}, format="json")
            assert response.status_code == status.HTTP_200_OK
            assert response.data["message"] == "파일이 성공적으로 삭제되었습니다."

    def test_delete_without_auth(self, api_client):
        """인증 없이 삭제 - 실패"""
        response = api_client.delete("/api/s3/delete/", {"key": "avatars/test.png"}, format="json")
        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_delete_without_key(self, authenticated_client):
        """키 없이 삭제 - 실패"""
        response = authenticated_client.delete("/api/s3/delete/", {}, format="json")
        assert response.status_code == status.HTTP_400_BAD_REQUEST
