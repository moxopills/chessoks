"""비밀번호 재설정 시리얼라이저"""

import re

from rest_framework import serializers


class PasswordResetRequestSerializer(serializers.Serializer):
    """비밀번호 재설정 요청"""

    email = serializers.EmailField(help_text="가입된 이메일 주소")


class PasswordResetConfirmSerializer(serializers.Serializer):
    """비밀번호 재설정 확인"""

    token = serializers.CharField(help_text="이메일로 받은 토큰")
    new_password = serializers.CharField(write_only=True, help_text="새 비밀번호")
    new_password2 = serializers.CharField(write_only=True, help_text="비밀번호 확인")

    def validate_new_password(self, value):
        """비밀번호 검증 (회원가입과 동일한 규칙)"""
        if len(value) < 8:
            raise serializers.ValidationError("비밀번호는 최소 8자 이상이어야 합니다.")
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("비밀번호에 대문자가 최소 1개 포함되어야 합니다.")
        if not re.search(r"[!*@]", value):
            raise serializers.ValidationError(
                "비밀번호에 특수문자 (!, *, @) 중 1개 이상 포함되어야 합니다."
            )
        return value

    def validate(self, attrs):
        """비밀번호 일치 확인"""
        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError({"new_password": "비밀번호가 일치하지 않습니다."})
        return attrs
