"""Chess 앱 공통 유틸리티"""


def parse_int(value, default: int, min_value: int, max_value: int) -> int:
    """쿼리 파라미터를 정수로 변환 (범위 제한 포함)"""
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(min_value, min(parsed, max_value))
