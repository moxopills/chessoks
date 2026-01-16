"""통일된 에러 응답 처리"""

from rest_framework import status
from rest_framework.exceptions import APIException
from rest_framework.views import exception_handler

ERROR_CODES = {
    "ValidationError": "validation_error",
    "AuthenticationFailed": "authentication_failed",
    "NotAuthenticated": "not_authenticated",
    "PermissionDenied": "permission_denied",
    "Throttled": "throttled",
    "NotFound": "not_found",
    "MethodNotAllowed": "method_not_allowed",
}


def custom_exception_handler(exc, context):
    """
    통일된 에러 응답 포맷:
    {
        "error": {
            "code": "validation_error",
            "message": "유효성 검증에 실패했습니다.",
            "details": {"email": ["이미 사용 중인 이메일입니다."]}
        }
    }
    """
    response = exception_handler(exc, context)

    if response is None:
        return None

    error_code = ERROR_CODES.get(exc.__class__.__name__, "error")
    error_data = {"code": error_code}

    # ValidationError: 필드별 에러
    if hasattr(exc, "detail"):
        detail = exc.detail

        if isinstance(detail, dict):
            # {"field": ["message"]} 또는 {"non_field_errors": ["message"]}
            if "non_field_errors" in detail:
                error_data["message"] = detail["non_field_errors"][0]
                remaining = {
                    key: value for key, value in detail.items() if key != "non_field_errors"
                }
                if remaining:
                    error_data["details"] = remaining
            else:
                error_data["message"] = _get_first_error_message(detail)
                error_data["details"] = detail
        elif isinstance(detail, list):
            error_data["message"] = detail[0] if detail else "오류가 발생했습니다."
        else:
            error_data["message"] = str(detail)
    else:
        error_data["message"] = "오류가 발생했습니다."

    response.data = {"error": error_data}
    return response


def _get_first_error_message(details: dict) -> str:
    """첫 번째 에러 메시지 추출"""
    for messages in details.values():
        if isinstance(messages, list) and messages:
            return str(messages[0])
        if messages:
            return str(messages)
    return "유효성 검증에 실패했습니다."


class ServiceException(APIException):
    """서비스 레이어에서 사용하는 커스텀 예외"""

    status_code = status.HTTP_400_BAD_REQUEST
    default_code = "service_error"

    def __init__(self, message: str, code: str = None, details: dict = None):
        self.detail = {"message": message}
        if code:
            self.detail["code"] = code
        if details:
            self.detail["details"] = details
