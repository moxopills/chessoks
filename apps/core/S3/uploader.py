from __future__ import annotations

import logging
from collections.abc import Callable
from functools import lru_cache, wraps
from typing import Any

from django.conf import settings

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ParamValidationError,
)
from rest_framework.exceptions import APIException, ValidationError

logger = logging.getLogger(__name__)


def handle_s3_errors(operation: str) -> Callable[..., Any]:
    """S3 작업 에러 핸들링 데코레이터"""

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return func(*args, **kwargs)
            except ValidationError:
                raise
            except APIException:
                raise
            except NoCredentialsError as e:
                logger.error("S3 credentials not found", exc_info=True)
                raise APIException("S3 자격 증명을 찾을 수 없습니다.") from e
            except ClientError as e:
                error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
                logger.error(f"S3 ClientError: {error_code}", exc_info=True)
                raise APIException(f"{operation} 중 오류가 발생했습니다: {error_code}") from e
            except ParamValidationError as e:
                logger.error("S3 ParamValidationError", exc_info=True)
                raise APIException(f"잘못된 파라미터입니다: {str(e)}") from e
            except BotoCoreError as e:
                logger.error("S3 BotoCoreError", exc_info=True)
                raise APIException(f"S3 연결 중 오류가 발생했습니다: {str(e)}") from e
            except Exception as e:
                logger.error("S3 Unexpected Error", exc_info=True)
                raise APIException(f"예상치 못한 오류가 발생했습니다: {str(e)}") from e

        return wrapper

    return decorator


class S3Uploader:
    """
    공통 S3 업로더 클래스 (boto3 기반)
    - boto3 클라이언트 생성
    - 파일 삭제
    """

    @staticmethod
    @lru_cache(maxsize=1)
    def get_s3_client() -> Any:
        """S3 클라이언트 반환 (thread-safe lazy initialization)"""
        return boto3.client(
            "s3",
            aws_access_key_id=getattr(settings, "AWS_S3_ACCESS_KEY_ID", None),
            aws_secret_access_key=getattr(settings, "AWS_S3_SECRET_ACCESS_KEY", None),
            region_name=getattr(settings, "AWS_S3_REGION", None),
        )

    @classmethod
    def get_bucket_name(cls) -> str:
        """S3 버킷 이름 반환"""
        return getattr(settings, "AWS_S3_BUCKET_NAME", "")

    @classmethod
    def get_s3_base_url(cls) -> str:
        """S3 Base URL 반환"""
        bucket = cls.get_bucket_name()
        region = getattr(settings, "AWS_S3_REGION", "")
        return f"https://{bucket}.s3.{region}.amazonaws.com/"

    @classmethod
    @handle_s3_errors("파일 삭제")
    def delete_file(cls, key: str) -> dict[str, Any]:
        """
        S3 파일 삭제 (단일)

        Args:
            key: S3 객체 키 (예: uploads/recruitments/images/uuid.png)

        Returns:
            dict: 삭제 결과
                - message: 성공 메시지
                - key: 삭제된 객체 키

        Raises:
            ValidationError: key가 비어있거나 파일이 존재하지 않을 경우
            APIException: S3 삭제 실패
        """
        if not key or not key.strip():
            raise ValidationError("key는 필수입니다.")

        try:
            cls.get_s3_client().head_object(Bucket=cls.get_bucket_name(), Key=key)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code == "404":
                raise ValidationError(f"파일이 존재하지 않습니다: {key}") from e
            raise

        cls.get_s3_client().delete_object(
            Bucket=cls.get_bucket_name(),
            Key=key,
        )

        return {
            "message": "파일이 성공적으로 삭제되었습니다.",
            "key": key,
        }


s3_uploader = S3Uploader()
