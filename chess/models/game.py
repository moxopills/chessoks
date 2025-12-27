from django.conf import settings
from django.db import models

from .room import Room


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

    class Meta:
        db_table = "games"
        verbose_name = "게임"
        verbose_name_plural = "게임"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["result"]),
            models.Index(fields=["white_player", "black_player"]),
        ]

    def __str__(self):
        return f"{self.white_player.nickname} vs {self.black_player.nickname} - {self.get_result_display()}"

    def save(self, *args, **kwargs):
        """게임 저장 시 초기 시간 설정"""
        if not self.pk:  # 새로 생성되는 경우
            time_limit_seconds = self.room.time_limit * 60
            self.white_time_remaining = time_limit_seconds
            self.black_time_remaining = time_limit_seconds
        super().save(*args, **kwargs)

    @property
    def is_finished(self):
        """게임 종료 여부"""
        return self.result != "playing"

    @property
    def winner(self):
        """승자 반환"""
        if self.result in ["white_win", "checkmate_white", "timeout_black", "resignation_black"]:
            return self.white_player
        elif self.result in ["black_win", "checkmate_black", "timeout_white", "resignation_white"]:
            return self.black_player
        return None

    def finish_game(self, result):
        """게임 종료 처리

        Args:
            result (str): 게임 결과 ('checkmate_white', 'timeout_black' 등)
        """
        from django.utils import timezone

        self.result = result
        self.finished_at = timezone.now()
        self.save()

        # 방 상태 업데이트
        self.room.status = "finished"
        self.room.finished_at = timezone.now()
        self.room.save()

        # 플레이어 통계 업데이트
        self._update_player_stats()

    def _update_player_stats(self):
        """플레이어 통계 및 레이팅 업데이트"""
        winner = self.winner

        if winner == self.white_player:
            # 백 승리
            self.white_player.update_stats("win")
            self.black_player.update_stats("loss")
            self.white_player.update_rating(self.black_player.rating, 1.0)
            self.black_player.update_rating(self.white_player.rating, 0.0)
        elif winner == self.black_player:
            # 흑 승리
            self.black_player.update_stats("win")
            self.white_player.update_stats("loss")
            self.black_player.update_rating(self.white_player.rating, 1.0)
            self.white_player.update_rating(self.black_player.rating, 0.0)
        else:
            # 무승부
            self.white_player.update_stats("draw")
            self.black_player.update_stats("draw")
            self.white_player.update_rating(self.black_player.rating, 0.5)
            self.black_player.update_rating(self.white_player.rating, 0.5)

    def make_move(self, move_data, fen_after_move):
        """착수 처리

        Args:
            move_data (dict): 착수 정보 (from, to, piece 등)
            fen_after_move (str): 착수 후 FEN 상태
        """
        # FEN 업데이트
        self.fen = fen_after_move

        # 수 카운트 증가
        self.move_count += 1

        # 차례 변경
        self.current_turn = "black" if self.current_turn == "white" else "white"

        self.save()

    def update_time(self, player_color, time_remaining):
        """플레이어 남은 시간 업데이트

        Args:
            player_color (str): 'white' 또는 'black'
            time_remaining (int): 남은 시간 (초)
        """
        if player_color == "white":
            self.white_time_remaining = time_remaining
        else:
            self.black_time_remaining = time_remaining

        # 시간 초과 체크
        if time_remaining <= 0:
            if player_color == "white":
                self.finish_game("timeout_white")
            else:
                self.finish_game("timeout_black")
        else:
            self.save()
