"""S3 이미지 업로드 상수 및 설정"""

from __future__ import annotations

from enum import Enum
from typing import ClassVar


class FileType(str, Enum):
    """이미지 파일 타입"""

    USER_AVATAR = "user_avatar"  # 유저 프로필 이미지


class S3Constants:
    """S3 이미지 업로드 상수"""

    # 파일 크기 제한
    MAX_FILE_SIZE_MB: ClassVar[int] = 10
    MAX_FILE_SIZE_BYTES: ClassVar[int] = MAX_FILE_SIZE_MB * 1024 * 1024
    MIN_FILE_SIZE_BYTES: ClassVar[int] = 1

    # 허용 이미지 확장자
    ALLOWED_EXTENSIONS: ClassVar[set[str]] = {"jpg", "jpeg", "png", "gif", "webp"}

    # MIME 타입 매핑
    MIME_BY_EXT: ClassVar[dict[str, set[str]]] = {
        "jpg": {"image/jpeg"},
        "jpeg": {"image/jpeg"},
        "png": {"image/png"},
        "gif": {"image/gif"},
        "webp": {"image/webp"},
    }

    # S3 업로드 경로 매핑
    PATH_MAPPING: ClassVar[dict[FileType, str]] = {
        FileType.USER_AVATAR: "avatars",
    }

    @classmethod
    def get_all_mime_types(cls) -> set[str]:
        """모든 허용된 MIME 타입 반환"""
        return {mime for mimes in cls.MIME_BY_EXT.values() for mime in mimes}
