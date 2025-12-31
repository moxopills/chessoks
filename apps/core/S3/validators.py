"""S3 이미지 파일 검증"""

from __future__ import annotations

from rest_framework.exceptions import ValidationError

from .constants import S3Constants


class S3ImageValidator:
    """S3 이미지 파일 검증 클래스 (간소화 버전)"""

    @staticmethod
    def validate_file_name(file_name: str) -> None:
        """파일명 검증"""
        if not file_name or "." not in file_name or not file_name.rsplit(".", 1)[0]:
            raise ValidationError("유효하지 않은 파일명입니다.")

    @staticmethod
    def validate_extension(file_name: str, file_ext: str) -> str:
        """파일 확장자 검증 (파일명과 파라미터 일치 확인)"""
        ext = file_name.rsplit(".", 1)[-1].lower()

        if ext not in S3Constants.ALLOWED_EXTENSIONS:
            raise ValidationError(
                f"허용된 확장자만 사용 가능합니다. ({', '.join(S3Constants.ALLOWED_EXTENSIONS)})"
            )

        if ext != file_ext.lower():
            raise ValidationError(
                f"파일명 확장자({ext})와 요청 확장자({file_ext})가 일치하지 않습니다."
            )

        return ext

    @staticmethod
    def validate_mime_type(ext: str, content_type: str) -> None:
        """MIME 타입 검증"""
        if not content_type:
            raise ValidationError("Content-Type이 필요합니다.")

        allowed_mimes = S3Constants.MIME_BY_EXT.get(ext)
        if not allowed_mimes or content_type not in allowed_mimes:
            raise ValidationError(
                f"{ext} 확장자에 허용된 MIME 타입이 아닙니다. "
                f"({', '.join(allowed_mimes) if allowed_mimes else '없음'})"
            )

    @staticmethod
    def validate_file_size(file_size: int | None) -> None:
        """파일 크기 검증"""
        if file_size is None:
            raise ValidationError("파일 크기를 확인할 수 없습니다.")

        if file_size > S3Constants.MAX_FILE_SIZE_BYTES:
            raise ValidationError(f"{S3Constants.MAX_FILE_SIZE_MB}MB 이하만 업로드 가능합니다.")
