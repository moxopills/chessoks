"""비밀번호 검증 유틸리티"""

import string

from rest_framework import serializers


def validate_password_strength(password: str) -> str:
    """비밀번호 강도 검증

    요구사항:
    - 최소 8자 이상
    - 대문자 1개 이상
    - 소문자 1개 이상
    - 숫자 1개 이상
    - 특수문자 1개 이상

    Args:
        password: 검증할 비밀번호

    Returns:
        검증된 비밀번호

    Raises:
        serializers.ValidationError: 비밀번호가 요구사항을 충족하지 않을 때
    """
    if len(password) < 8:
        raise serializers.ValidationError("비밀번호는 최소 8자 이상이어야 합니다.")

    if not any(c.isupper() for c in password):
        raise serializers.ValidationError("비밀번호에 대문자가 최소 1개 포함되어야 합니다.")

    if not any(c.islower() for c in password):
        raise serializers.ValidationError("비밀번호에 소문자가 최소 1개 포함되어야 합니다.")

    if not any(c.isdigit() for c in password):
        raise serializers.ValidationError("비밀번호에 숫자가 최소 1개 포함되어야 합니다.")

    if not any(c in string.punctuation for c in password):
        raise serializers.ValidationError("비밀번호에 특수문자가 최소 1개 포함되어야 합니다.")

    return password
