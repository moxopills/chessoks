from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    """커스텀 유저 매니저"""

    def create_user(self, email, nickname, password=None, **extra_fields):
        """일반 유저 생성 + UserStats 자동 생성"""
        if not email:
            raise ValueError("이메일은 필수입니다")
        if not nickname:
            raise ValueError("닉네임은 필수입니다")

        email = self.normalize_email(email)

        user = self.model(email=email, nickname=nickname, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)

        # UserStats 자동 생성
        from apps.accounts.models import UserStats

        UserStats.objects.create(user=user)

        return user

    def create_superuser(self, email, nickname, password=None, **extra_fields):
        """슈퍼유저 생성"""
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        return self.create_user(email, nickname, password, **extra_fields)

    def top_players(self, limit=10):
        """상위 레이팅 플레이어 (UserStats의 rating 기준)"""
        return (
            self.filter(is_active=True).select_related("stats").order_by("-stats__rating")[:limit]
        )

    def active_players(self):
        """활성 플레이어"""
        return self.filter(is_active=True)


class User(AbstractBaseUser, PermissionsMixin):
    """커스텀 유저 모델 - 이메일 로그인 + 닉네임 기반

    Note:
    - 이메일로 로그인 (USERNAME_FIELD = "email")
    - 게임 통계는 UserStats 모델로 분리
    - username 필드 없음 (nickname만 사용)
    """

    email = models.EmailField(
        unique=True,
        db_index=True,
        help_text="이메일 주소 (로그인 ID)",
    )
    nickname = models.CharField(max_length=50, unique=True, help_text="게임 내 표시 이름")
    avatar_url = models.URLField(
        max_length=500, blank=True, null=True, help_text="S3 프로필 사진 URL"
    )
    bio = models.TextField(blank=True, help_text="자기소개")

    # 이메일 인증
    email_verified = models.BooleanField(default=False, help_text="이메일 인증 완료 여부")
    email_verified_at = models.DateTimeField(
        null=True, blank=True, help_text="이메일 인증 완료 시간"
    )

    # Django Admin용 필드
    is_staff = models.BooleanField(default=False, help_text="관리자 권한")
    is_active = models.BooleanField(default=True, help_text="활성 계정")
    date_joined = models.DateTimeField(default=timezone.now, help_text="가입일")

    # 회원 탈퇴 예약
    scheduled_deletion_at = models.DateTimeField(
        null=True, blank=True, help_text="탈퇴 예정 시간 (이 시간 전에 로그인하면 취소)"
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = ["nickname"]

    class Meta:
        db_table = "users"
        verbose_name = "사용자"
        verbose_name_plural = "사용자"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.nickname} ({self.email})"
