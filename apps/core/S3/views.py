"""S3 이미지 업로드 및 삭제 View"""

import uuid

from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .constants import FileType, S3Constants
from .uploader import s3_uploader
from .validators import S3ImageValidator


class S3DirectUploadView(APIView):
    """백엔드에서 직접 S3로 업로드 (multipart/form-data)"""

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    @extend_schema(
        summary="이미지 직접 업로드",
        description="파일을 받아서 백엔드에서 직접 S3로 업로드합니다.",
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
                            "file_url": "https://chessok.s3.ap-northeast-2.amazonaws.com/avatars/uuid.png",
                            "key": "avatars/uuid.png",
                        }
                    }
                },
            }
        },
        tags=["S3"],
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
        S3ImageValidator.validate_file_name(file_name)
        ext = file_name.rsplit(".", 1)[-1].lower()
        S3ImageValidator.validate_extension(file_name, ext)
        S3ImageValidator.validate_mime_type(ext, content_type)
        S3ImageValidator.validate_file_size(file.size)

        # S3 키 생성
        prefix = S3Constants.PATH_MAPPING.get(file_type_enum)
        key = f"{prefix}/{uuid.uuid4()}.{ext}"

        # S3 업로드
        s3_client = s3_uploader.get_s3_client()
        bucket = s3_uploader.get_bucket_name()

        s3_client.upload_fileobj(
            file.file,
            bucket,
            key,
            ExtraArgs={"ContentType": content_type},
        )

        file_url = f"{s3_uploader.get_s3_base_url()}{key}"

        return Response(
            {
                "message": "업로드 성공",
                "file_url": file_url,
                "key": key,
            },
            status=status.HTTP_200_OK,
        )


class S3FileDeleteView(APIView):
    """S3 이미지 삭제"""

    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="S3 이미지 삭제",
        description="S3 객체 키로 이미지를 삭제합니다.",
        request={
            "application/json": {"type": "object", "properties": {"key": {"type": "string"}}, "required": ["key"]}
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
                                "value": {"error_detail": "파일이 존재하지 않습니다: avatars/example.png"},
                            },
                        }
                    }
                },
            },
            401: {
                "description": "인증 실패",
                "content": {
                    "application/json": {"example": {"error_detail": "자격 인증 데이터가 제공되지 않았습니다."}}
                },
            },
        },
        tags=["S3"],
    )
    def delete(self, request: Request) -> Response:
        key = request.data.get("key", "")
        result = s3_uploader.delete_file(key=key)
        return Response(result, status=status.HTTP_200_OK)
