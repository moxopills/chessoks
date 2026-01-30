import logging
from collections.abc import Callable
from functools import lru_cache, wraps
from typing import Any

from django.conf import settings

from google.api_core.exceptions import GoogleAPIError, NotFound
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import storage
from rest_framework.exceptions import APIException, ValidationError

logger = logging.getLogger(__name__)


def handle_gcp_errors(operation: str) -> Callable[..., Any]:
    """GCP 작업 에러 핸들링 데코레이터"""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except ValidationError:
                raise
            except APIException:
                raise
            except DefaultCredentialsError as e:
                logger.error("GCS credentials not found", exc_info=True)
                raise APIException("GCS 자격 증명을 찾을 수 없습니다.") from e
            except GoogleAPIError as e:
                logger.error("GCS API error", exc_info=True)
                raise APIException(f"{operation} 중 오류가 발생했습니다: {str(e)}") from e
            except Exception as e:
                logger.error("GCS Unexpected Error", exc_info=True)
                raise APIException(f"예상치 못한 오류가 발생했습니다: {str(e)}") from e

        return wrapper

    return decorator


class GCPUploader:
    """
    공통 스토리지 업로더 클래스 (GCS 기반)
    - GCS 클라이언트 생성
    - 파일 삭제
    """

    @staticmethod
    @lru_cache(maxsize=1)
    def get_client() -> Any:
        """GCP 클라이언트 반환 (thread-safe lazy initialization)"""
        credentials_path = getattr(settings, "GCS_CREDENTIALS_JSON", "")
        if credentials_path:
            return storage.Client.from_service_account_json(credentials_path)
        return storage.Client()

    @classmethod
    def get_bucket_name(cls) -> str:
        """GCS 버킷 이름 반환"""
        return getattr(settings, "GCS_BUCKET_NAME", "")

    @classmethod
    def get_base_url(cls) -> str:
        """GCP Base URL 반환"""
        bucket = cls.get_bucket_name()
        base_url = getattr(settings, "GCS_BASE_URL", "")
        if base_url:
            return base_url.rstrip("/") + "/"
        return f"https://storage.googleapis.com/{bucket}/"

    @classmethod
    def extract_key_from_url(cls, url: str) -> str | None:
        """
        GCS URL에서 키 추출

        Args:
            url: GCS 파일 URL (예: https://storage.googleapis.com/bucket/avatars/uuid.png)

        Returns:
            str | None: GCS 객체 키 (예: avatars/uuid.png) 또는 None
        """
        if not url:
            return None

        base_url = cls.get_base_url()
        if url.startswith(base_url):
            return url[len(base_url) :]

        bucket = cls.get_bucket_name()
        alt_base = f"https://{bucket}.storage.googleapis.com/"
        if url.startswith(alt_base):
            return url[len(alt_base) :]

        return None

    @classmethod
    @handle_gcp_errors("파일 업로드")
    def upload_fileobj(cls, file_obj: Any, key: str, content_type: str | None = None) -> None:
        """GCP 파일 업로드"""
        if not key or not key.strip():
            raise ValidationError("key는 필수입니다.")

        client = cls.get_client()
        bucket = client.bucket(cls.get_bucket_name())
        blob = bucket.blob(key)
        blob.upload_from_file(file_obj, content_type=content_type, predefined_acl="publicRead")
        try:
            blob.make_public()
        except Exception:
            # 버킷 정책이 public ACL을 허용하지 않아도 업로드는 유지
            logger.warning("GCS object is not public; check bucket IAM or ACL settings.")

    @classmethod
    @handle_gcp_errors("파일 삭제")
    def delete_file(cls, key: str) -> dict[str, Any]:
        """
        GCS 파일 삭제 (단일)

        Args:
            key: GCP 객체 키 (예: uploads/recruitments/images/uuid.png)

        Returns:
            dict: 삭제 결과
                - message: 성공 메시지
                - key: 삭제된 객체 키

        Raises:
            ValidationError: key가 비어있거나 파일이 존재하지 않을 경우
            APIException: GCS 삭제 실패
        """
        if not key or not key.strip():
            raise ValidationError("key는 필수입니다.")

        client = cls.get_client()
        bucket = client.bucket(cls.get_bucket_name())
        blob = bucket.blob(key)
        try:
            exists = blob.exists(client=client)
        except NotFound as e:
            raise ValidationError(f"파일이 존재하지 않습니다: {key}") from e

        if not exists:
            raise ValidationError(f"파일이 존재하지 않습니다: {key}")

        blob.delete(client=client)

        return {
            "message": "파일이 성공적으로 삭제되었습니다.",
            "key": key,
        }


gcp_uploader = GCPUploader()
