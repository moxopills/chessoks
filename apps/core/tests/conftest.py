"""Pytest 설정 및 공통 Fixtures"""

import pytest
from django.contrib.auth import get_user_model
from faker import Faker
from rest_framework.test import APIClient

User = get_user_model()
fake = Faker("ko_KR")


@pytest.fixture
def api_client():
    """API 클라이언트"""
    return APIClient()


@pytest.fixture
def user_data():
    """테스트용 유저 데이터"""
    return {
        "email": fake.email(),
        "nickname": fake.user_name(),
        "password": "TestPass123!@#",
    }


@pytest.fixture
def create_user(db):
    """유저 생성 팩토리"""

    def _create_user(**kwargs):
        defaults = {
            "email": fake.email(),
            "nickname": fake.user_name(),
            "password": "TestPass123!@#",
        }
        defaults.update(kwargs)
        password = defaults.pop("password")
        user = User.objects.create_user(**defaults, password=password)
        user.raw_password = password  # 테스트용으로 저장
        return user

    return _create_user


@pytest.fixture
def authenticated_client(api_client, create_user):
    """인증된 API 클라이언트"""
    user = create_user()
    api_client.force_authenticate(user=user)
    api_client.user = user
    return api_client


@pytest.fixture
def verified_user(create_user):
    """이메일 인증 완료된 유저"""
    user = create_user()
    user.email_verified = True
    user.save()
    return user
