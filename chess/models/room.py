from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ValidationError
from django.db import models


class RoomManager(models.Manager):
    """Room 커스텀 매니저"""

    def available_rooms(self):
        """입장 가능한 방 목록"""
        return self.filter(status="waiting", is_private=False, guest__isnull=True)

    def user_rooms(self, user):
        """유저가 속한 방 목록"""
        return self.filter(models.Q(host=user) | models.Q(guest=user))


class Room(models.Model):
    """체스 게임 방 - 빠른 대전 / 사용자 방"""

    ROOM_TYPE_CHOICES = [
        ("quick", "빠른 대전"),
        ("custom", "사용자 방"),
    ]

    STATUS_CHOICES = [
        ("waiting", "대기 중"),
        ("playing", "게임 중"),
        ("finished", "종료"),
    ]

    # 방 타입
    room_type = models.CharField(
        max_length=10,
        choices=ROOM_TYPE_CHOICES,
        default="custom",
        help_text="빠른 대전 또는 사용자 방",
    )

    # 방 제목 (custom일 때만 사용)
    title = models.CharField(max_length=100, blank=True, help_text="사용자 방 제목")

    # 방장
    host = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="hosted_rooms",
        help_text="방을 만든 사용자",
    )

    # 게스트 (참가자)
    guest = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="joined_rooms",
        null=True,
        blank=True,
        help_text="참가한 사용자",
    )

    # 방 상태
    status = models.CharField(
        max_length=20, choices=STATUS_CHOICES, default="waiting", help_text="방 상태"
    )

    # 비공개방 여부
    is_private = models.BooleanField(default=False, help_text="비공개방 여부")

    # 비밀번호 (비공개방일 때)
    password = models.CharField(max_length=50, blank=True, help_text="방 비밀번호")

    # 관전 허용 여부
    allow_spectators = models.BooleanField(default=True, help_text="관전 허용 여부")

    # 관전자 목록
    spectators = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        related_name="spectating_rooms",
        blank=True,
        help_text="현재 관전 중인 사용자들",
    )

    # 시간 제한 (분)
    time_limit = models.IntegerField(default=30, help_text="각 플레이어당 시간 제한 (분)")

    # 타임스탬프
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    objects = RoomManager()

    class Meta:
        db_table = "rooms"
        verbose_name = "방"
        verbose_name_plural = "방"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "room_type"]),
            models.Index(fields=["host"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(time_limit__gt=0), name="time_limit_positive"
            ),
        ]

    def __str__(self):
        if self.room_type == "quick":
            return f"빠른 대전 - {self.host.nickname}"
        return f"{self.title} - {self.host.nickname}"

    def clean(self):
        """모델 검증"""
        super().clean()
        if self.is_private and not self.password:
            raise ValidationError("비공개방은 비밀번호가 필요합니다")
        if self.time_limit <= 0:
            raise ValidationError("시간 제한은 양수여야 합니다")
        if self.host == self.guest:
            raise ValidationError("호스트와 게스트가 동일할 수 없습니다")

    def set_password(self, raw_password):
        """비밀번호 해싱하여 저장"""
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        """비밀번호 확인"""
        return check_password(raw_password, self.password)

    @property
    def is_full(self):
        """방이 가득 찼는지 확인 (읽기 전용 property)"""
        return self.guest is not None

    @property
    def player_count(self):
        """현재 플레이어 수 (읽기 전용 property)"""
        return 2 if self.is_full else 1
