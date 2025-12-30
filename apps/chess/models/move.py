import re

from django.core.exceptions import ValidationError
from django.db import models

from .game import Game


class Move(models.Model):
    """체스 착수 기록 모델

    각 착수를 기록하고 게임 히스토리를 추적합니다.
    SAN (Standard Algebraic Notation) 표기법을 사용합니다.

    SAN 표기법 예시:
    - e4: 폰을 e4로 이동
    - Nf3: 나이트를 f3로 이동
    - Bxc6: 비숍으로 c6의 기물을 잡음
    - O-O: 킹사이드 캐슬링
    - O-O-O: 퀸사이드 캐슬링
    - e8=Q: 폰을 퀸으로 승진
    - Nxe5+: 나이트로 e5를 잡고 체크
    - Qh5#: 퀸을 h5로 이동하여 체크메이트
    """

    PIECE_CHOICES = [
        ("P", "Pawn (폰)"),
        ("N", "Knight (나이트)"),
        ("B", "Bishop (비숍)"),
        ("R", "Rook (룩)"),
        ("Q", "Queen (퀸)"),
        ("K", "King (킹)"),
    ]

    # 게임
    game = models.ForeignKey(
        Game, on_delete=models.CASCADE, related_name="moves", help_text="착수가 속한 게임"
    )

    # 착수 번호 (1, 2, 3, ...)
    move_number = models.IntegerField(help_text="착수 번호 (1부터 시작)")

    # 플레이어 색상
    player_color = models.CharField(
        max_length=5, choices=[("white", "백"), ("black", "흑")], help_text="착수한 플레이어의 색상"
    )

    # 이동한 기물
    piece = models.CharField(max_length=1, choices=PIECE_CHOICES, help_text="이동한 체스 기물")

    # 출발 위치 (예: e2)
    from_square = models.CharField(max_length=2, help_text="출발 위치 (예: e2, a1)")

    # 도착 위치 (예: e4)
    to_square = models.CharField(max_length=2, help_text="도착 위치 (예: e4, h8)")

    # SAN 표기법 (예: Nf3, e4, O-O)
    san = models.CharField(max_length=10, help_text="Standard Algebraic Notation")

    # UCI 표기법 (예: e2e4, e7e5)
    uci = models.CharField(max_length=5, help_text="Universal Chess Interface notation")

    # 캡처 여부
    is_capture = models.BooleanField(default=False, help_text="기물을 잡았는지 여부")

    # 체크 여부
    is_check = models.BooleanField(default=False, help_text="체크 상태인지 여부")

    # 체크메이트 여부
    is_checkmate = models.BooleanField(default=False, help_text="체크메이트 상태인지 여부")

    # 캐슬링 여부
    is_castling = models.BooleanField(default=False, help_text="캐슬링 착수인지 여부")

    # 앙파상 여부
    is_en_passant = models.BooleanField(default=False, help_text="앙파상 착수인지 여부")

    # 프로모션 여부 및 승진 기물
    promotion = models.CharField(
        max_length=1,
        blank=True,
        choices=[
            ("Q", "Queen"),
            ("R", "Rook"),
            ("B", "Bishop"),
            ("N", "Knight"),
        ],
        help_text="폰 승진 시 선택한 기물",
    )

    # 착수 후 FEN
    fen_after_move = models.CharField(max_length=100, help_text="착수 후 보드 상태 (FEN)")

    # 착수 시간 (소요 시간, 초)
    time_spent = models.FloatField(null=True, blank=True, help_text="이번 착수에 소요된 시간 (초)")

    # 타임스탬프
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "moves"
        verbose_name = "착수"
        verbose_name_plural = "착수"
        ordering = ["game", "move_number", "player_color"]
        indexes = [
            models.Index(fields=["game", "move_number"]),
            models.Index(fields=["game", "created_at"]),
        ]
        unique_together = [["game", "move_number", "player_color"]]

    def __str__(self):
        return f"Move {self.move_number}: {self.san} ({self.player_color})"

    def clean(self):
        """모델 검증"""
        super().clean()

        # 체스 좌표 검증 (a1-h8)
        square_pattern = re.compile(r"^[a-h][1-8]$")
        if not square_pattern.match(self.from_square):
            raise ValidationError(f"잘못된 출발 좌표: {self.from_square}")
        if not square_pattern.match(self.to_square):
            raise ValidationError(f"잘못된 도착 좌표: {self.to_square}")

        # 체크와 체크메이트는 동시에 불가
        if self.is_check and self.is_checkmate:
            raise ValidationError("체크와 체크메이트는 동시에 참일 수 없습니다")

        # 착수 번호 양수 검증
        if self.move_number <= 0:
            raise ValidationError("착수 번호는 1 이상이어야 합니다")

    @property
    def full_move_notation(self):
        """완전한 착수 표기 (체크, 체크메이트 표시 포함)"""
        notation = self.san
        if self.is_checkmate:
            notation += "#"
        elif self.is_check:
            notation += "+"
        return notation
