"""GCP 이미지 업로드 및 삭제 View"""

import uuid

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.throttling import AvatarUploadThrottle

from .constants import FileType, GCPConstants
from .uploader import gcp_uploader
from .validators import GCPImageValidator


class GCPDirectUploadView(APIView):
    """백엔드에서 직접 GCP로 업로드 (multipart/form-data)"""

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]
    throttle_classes = [AvatarUploadThrottle]

    @extend_schema(
        summary="이미지 직접 업로드",
        description="GCP 파일 업로드",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {
                    "file": {"type": "string", "format": "binary"},
                    "type": {
                        "type": "string",
                        "enum": [ft.value for ft in FileType],
                        "default": "user_avatar",
                    },
                },
                "required": ["file"],
            }
        },
        responses={
            200: {
                "description": "업로드 성공",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "업로드 성공",
                            "file_url": "https://storage.googleapis.com/chessok/avatars/uuid.png",
                            "key": "avatars/uuid.png",
                        }
                    }
                },
            }
        },
        tags=["GCP"],
    )
    def post(self, request: Request) -> Response:
        """파일 업로드"""
        file = request.FILES.get("file")
        file_type = request.data.get("type", "user_avatar")

        if not file:
            return Response({"error": "파일이 필요합니다."}, status=status.HTTP_400_BAD_REQUEST)

        # 파일 타입 검증
        try:
            file_type_enum = FileType(file_type)
        except ValueError:
            return Response(
                {"error": f"유효하지 않은 파일 타입: {file_type}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # 파일명과 확장자 추출
        file_name = file.name
        content_type = file.content_type

        # 검증
        GCPImageValidator.validate_file_name(file_name)
        ext = file_name.rsplit(".", 1)[-1].lower()
        GCPImageValidator.validate_extension(file_name, ext)
        GCPImageValidator.validate_mime_type(ext, content_type)
        GCPImageValidator.validate_file_size(file.size)
        normalized_image = GCPImageValidator.normalize_image(file)

        # GCP 키 생성
        prefix = GCPConstants.PATH_MAPPING.get(file_type_enum)
        key = f"{prefix}/{uuid.uuid4()}.{normalized_image.extension}"

        # 스토리지 업로드 (GCP)
        gcp_uploader.upload_fileobj(
            normalized_image.content,
            key,
            content_type=normalized_image.content_type,
        )

        file_url = f"{gcp_uploader.get_base_url()}{key}"

        return Response(
            {
                "message": "업로드 성공",
                "file_url": file_url,
                "key": key,
            },
            status=status.HTTP_200_OK,
        )


class GCPFileDeleteView(APIView):
    """GCP 이미지 삭제"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="GCP 이미지 삭제",
        description="GCP 객체 키로 이미지를 삭제합니다.",
        request={
            "application/json": {
                "type": "object",
                "properties": {"key": {"type": "string"}},
                "required": ["key"],
            }
        },
        responses={
            200: {
                "description": "성공",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "파일이 성공적으로 삭제되었습니다.",
                            "key": "avatars/uuid.png",
                        }
                    }
                },
            },
            400: {
                "description": "잘못된 요청",
                "content": {
                    "application/json": {
                        "examples": {
                            "missing_key": {
                                "summary": "key 누락",
                                "value": {"error_detail": "key는 필수입니다."},
                            },
                            "file_not_found": {
                                "summary": "파일이 존재하지 않음",
                                "value": {
                                    "error_detail": "파일이 존재하지 않습니다: avatars/example.png"
                                },
                            },
                        }
                    }
                },
            },
            401: {
                "description": "인증 실패",
                "content": {
                    "application/json": {
                        "example": {"error_detail": "자격 인증 데이터가 제공되지 않았습니다."}
                    }
                },
            },
        },
        tags=["GCP"],
    )
    def delete(self, request: Request) -> Response:
        key = request.data.get("key", "")
        result = gcp_uploader.delete_file(key=key)
        return Response(result, status=status.HTTP_200_OK)
