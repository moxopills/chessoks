"""서비스 공통 유틸리티"""

from dataclasses import dataclass
from typing import Any

from rest_framework.exceptions import ValidationError


@dataclass(frozen=True)
class ServiceResult:
    status: int
    data: dict | None = None
    errors: dict | None = None
    payload: Any | None = None

    @property
    def ok(self) -> bool:
        return self.errors is None


def _ok(*, data: dict | None = None, payload: Any | None = None, status_code: int) -> ServiceResult:
    return ServiceResult(status=status_code, data=data, payload=payload)


def _validate_serializer(serializer) -> ServiceResult | None:
    if not serializer.is_valid():
        raise ValidationError(serializer.errors)
    return None
