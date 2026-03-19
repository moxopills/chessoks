"""GCP 이미지 파일 검증"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO

from PIL import Image, ImageOps, UnidentifiedImageError
from PIL.Image import DecompressionBombError
from rest_framework.exceptions import ValidationError

from .constants import GCPConstants


@dataclass
class NormalizedImage:
    content: BytesIO
    extension: str
    content_type: str
    width: int
    height: int


class GCPImageValidator:
    """GCP 이미지 파일 검증 클래스 (간소화 버전)"""

    @staticmethod
    def validate_file_name(file_name: str) -> None:
        """파일명 검증"""
        if not file_name or "." not in file_name or not file_name.rsplit(".", 1)[0]:
            raise ValidationError("유효하지 않은 파일명입니다.")

    @staticmethod
    def validate_extension(file_name: str, file_ext: str) -> str:
        """파일 확장자 검증 (파일명과 파라미터 일치 확인)"""
        ext = file_name.rsplit(".", 1)[-1].lower()

        if ext not in GCPConstants.ALLOWED_EXTENSIONS:
            raise ValidationError(
                f"허용된 확장자만 사용 가능합니다. ({', '.join(GCPConstants.ALLOWED_EXTENSIONS)})"
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

        allowed_mimes = GCPConstants.MIME_BY_EXT.get(ext)
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

        if file_size > GCPConstants.MAX_FILE_SIZE_BYTES:
            raise ValidationError(f"{GCPConstants.MAX_FILE_SIZE_MB}MB 이하만 업로드 가능합니다.")

    @staticmethod
    def normalize_image(file) -> NormalizedImage:
        """실제 이미지 디코드 후 안전한 포맷으로 재인코딩한다."""
        try:
            file.seek(0)
        except Exception:
            pass

        raw = file.read()
        GCPImageValidator.validate_file_size(len(raw))
        if not raw:
            raise ValidationError("비어 있는 파일은 업로드할 수 없습니다.")

        try:
            Image.MAX_IMAGE_PIXELS = GCPConstants.MAX_IMAGE_WIDTH * GCPConstants.MAX_IMAGE_HEIGHT
            image = Image.open(BytesIO(raw))
            image.load()
        except DecompressionBombError as exc:
            raise ValidationError("허용된 범위를 초과하는 이미지입니다.") from exc
        except (UnidentifiedImageError, OSError) as exc:
            raise ValidationError("실제 이미지 파일만 업로드할 수 있습니다.") from exc

        image = ImageOps.exif_transpose(image)
        width, height = image.size
        if width <= 0 or height <= 0:
            raise ValidationError("이미지 크기를 확인할 수 없습니다.")
        if width > GCPConstants.MAX_IMAGE_WIDTH or height > GCPConstants.MAX_IMAGE_HEIGHT:
            raise ValidationError(
                f"이미지 해상도는 {GCPConstants.MAX_IMAGE_WIDTH}x"
                f"{GCPConstants.MAX_IMAGE_HEIGHT} 이하만 허용됩니다."
            )

        has_alpha = image.mode in {"RGBA", "LA"} or (
            image.mode == "P" and "transparency" in image.info
        )
        if has_alpha:
            converted = image.convert("RGBA")
            output_format = "PNG"
            extension = "png"
            content_type = "image/png"
            save_kwargs = {"optimize": True}
        else:
            converted = image.convert("RGB")
            output_format = "WEBP"
            extension = "webp"
            content_type = "image/webp"
            save_kwargs = {"quality": 90, "method": 6}

        normalized = BytesIO()
        converted.save(normalized, format=output_format, **save_kwargs)
        normalized.seek(0)
        return NormalizedImage(
            content=normalized,
            extension=extension,
            content_type=content_type,
            width=width,
            height=height,
        )
