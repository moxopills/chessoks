from django.conf import settings
from django.db import models


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

    # 시간 제한 (분)
    time_limit = models.IntegerField(default=30, help_text="각 플레이어당 시간 제한 (분)")

    # 타임스탬프
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "rooms"
        verbose_name = "방"
        verbose_name_plural = "방"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "room_type"]),
            models.Index(fields=["host"]),
        ]

    def __str__(self):
        if self.room_type == "quick":
            return f"빠른 대전 - {self.host.nickname}"
        return f"{self.title} - {self.host.nickname}"

    @property
    def is_full(self):
        """방이 가득 찼는지 확인"""
        return self.guest is not None

    @property
    def player_count(self):
        """현재 플레이어 수"""
        return 2 if self.is_full else 1

    def can_join(self, user):
        """유저가 입장 가능한지 확인"""
        if self.is_full:
            return False, "방이 가득 찼습니다"
        if self.host == user:
            return False, "이미 입장한 방입니다"
        if self.status != "waiting":
            return False, "게임이 이미 시작되었습니다"
        return True, "입장 가능"

    def start_game(self):
        """게임 시작"""
        if not self.is_full:
            raise ValueError("플레이어가 부족합니다")

        from django.utils import timezone

        self.status = "playing"
        self.started_at = timezone.now()
        self.save()
