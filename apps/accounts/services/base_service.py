"""서비스 공통 유틸리티"""

from dataclasses import dataclass

from rest_framework.exceptions import ValidationError


@dataclass(frozen=True)
class ServiceResult:
    """서비스 결과 - JSON 응답 데이터와 HTTP 상태 코드"""

    data: dict
    status: int


def _ok(data: dict, status_code: int) -> ServiceResult:
    """성공 응답 생성"""
    return ServiceResult(data=data, status=status_code)


def _validate_serializer(serializer) -> None:
    """시리얼라이저 유효성 검증 - 실패 시 ValidationError 발생"""
    if not serializer.is_valid():
        raise ValidationError(serializer.errors)
