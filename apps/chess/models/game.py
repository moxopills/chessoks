from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models

from .room import Room


class GameManager(models.Manager):
    """Game 커스텀 매니저"""

    def ongoing_games(self):
        """진행 중인 게임"""
        return self.filter(result="playing")

    def finished_games(self):
        """종료된 게임"""
        return self.exclude(result="playing")

    def user_games(self, user):
        """유저가 참여한 게임"""
        return self.filter(models.Q(white_player=user) | models.Q(black_player=user))


class Game(models.Model):
    """체스 게임 모델 - 실제 게임 진행 및 결과 저장

    FEN (Forsyth-Edwards Notation) 설명:
    체스 보드의 현재 상태를 문자열로 표현하는 표준 기법

    예시: "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"

    구성 요소:
    1. 보드 배치 (rank 8부터 rank 1까지, '/'로 구분)
       - 대문자: 백 기물 (K=King, Q=Queen, R=Rook, B=Bishop, N=Knight, P=Pawn)
       - 소문자: 흑 기물 (k=king, q=queen, r=rook, b=bishop, n=knight, p=pawn)
       - 숫자: 연속된 빈 칸의 개수

    2. 현재 차례 (w=White/백, b=Black/흑)

    3. 캐슬링 가능 여부 (K=백 킹사이드, Q=백 퀸사이드, k=흑 킹사이드, q=흑 퀸사이드, -=불가능)

    4. 앙파상 가능 위치 (e3, d6 등의 좌표 또는 - 표시)

    5. 하프무브 카운터 (50수 규칙용)

    6. 풀무브 번호 (현재 턴 번호)

    Note: 비즈니스 로직은 chess.services.GameService 참조
    """

    RESULT_CHOICES = [
        ("playing", "진행 중"),
        ("white_win", "백 승리"),
        ("black_win", "흑 승리"),
        ("draw", "무승부"),
        ("stalemate", "스테일메이트"),
        ("checkmate_white", "체크메이트 - 백 승리"),
        ("checkmate_black", "체크메이트 - 흑 승리"),
        ("timeout_white", "시간 초과 - 흑 승리"),
        ("timeout_black", "시간 초과 - 백 승리"),
        ("resignation_white", "기권 - 흑 승리"),
        ("resignation_black", "기권 - 백 승리"),
        ("draw_agreement", "합의 무승부"),
        ("draw_repetition", "3회 반복 무승부"),
        ("draw_fifty_move", "50수 규칙 무승부"),
        ("draw_insufficient", "기물 부족 무승부"),
    ]

    # 게임이 속한 방
    room = models.OneToOneField(
        Room, on_delete=models.CASCADE, related_name="game", help_text="게임이 진행되는 방"
    )

    # 백 플레이어 (선공)
    white_player = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="games_as_white",
        help_text="백(White) 플레이어",
    )

    # 흑 플레이어 (후공)
    black_player = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="games_as_black",
        help_text="흑(Black) 플레이어",
    )

    # 현재 보드 상태 (FEN 표기법)
    fen = models.CharField(
        max_length=100,
        default="rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
        help_text="FEN 표기법으로 저장된 현재 보드 상태",
    )

    # 게임 기록 (PGN 표기법)
    pgn = models.TextField(blank=True, help_text="PGN(Portable Game Notation) 형식의 게임 기록")

    # 게임 결과
    result = models.CharField(
        max_length=20, choices=RESULT_CHOICES, default="playing", help_text="게임 결과"
    )

    # 총 수 (move count)
    move_count = models.IntegerField(default=0, help_text="총 착수 횟수")

    # 백 플레이어 남은 시간 (초)
    white_time_remaining = models.IntegerField(help_text="백 플레이어 남은 시간 (초)")

    # 흑 플레이어 남은 시간 (초)
    black_time_remaining = models.IntegerField(help_text="흑 플레이어 남은 시간 (초)")

    # 현재 차례
    current_turn = models.CharField(
        max_length=5,
        choices=[("white", "백"), ("black", "흑")],
        default="white",
        help_text="현재 차례 플레이어",
    )

    # 타임스탬프
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    objects = GameManager()

    class Meta:
        db_table = "games"
        verbose_name = "게임"
        verbose_name_plural = "게임"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["result"]),
            models.Index(fields=["white_player", "black_player"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=models.Q(move_count__gte=0), name="move_count_positive"
            ),
        ]

    def __str__(self):
        return f"{self.white_player.nickname} vs {self.black_player.nickname} - {self.get_result_display()}"

    def clean(self):
        """모델 검증"""
        super().clean()
        if self.white_player == self.black_player:
            raise ValidationError("백과 흑 플레이어가 동일할 수 없습니다")
        if self.move_count < 0:
            raise ValidationError("수 카운트는 음수가 될 수 없습니다")

    def save(self, *args, **kwargs):
        """게임 저장 시 초기 시간 설정"""
        if not self.pk:  # 새로 생성되는 경우
            time_limit_seconds = self.room.time_limit * 60
            self.white_time_remaining = time_limit_seconds
            self.black_time_remaining = time_limit_seconds
        super().save(*args, **kwargs)

    @property
    def is_finished(self):
        """게임 종료 여부 (읽기 전용 property)"""
        return self.result != "playing"

    @property
    def winner(self):
        """승자 반환 (읽기 전용 property)"""
        if self.result in ["white_win", "checkmate_white", "timeout_black", "resignation_black"]:
            return self.white_player
        elif self.result in ["black_win", "checkmate_black", "timeout_white", "resignation_white"]:
            return self.black_player
        return None
