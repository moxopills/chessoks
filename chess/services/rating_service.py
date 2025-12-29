"""레이팅 및 통계 관리 서비스"""


class RatingService:
    """ELO 레이팅 및 플레이어 통계 관리"""

    @staticmethod
    def calculate_new_rating(player_rating, opponent_rating, result, k_factor=32):
        """ELO 레이팅 계산

        Args:
            player_rating (int): 플레이어 현재 레이팅
            opponent_rating (int): 상대방 레이팅
            result (float): 1.0 (승리), 0.5 (무승부), 0.0 (패배)
            k_factor (int): K-factor (기본값 32)

        Returns:
            int: 새로운 레이팅
        """
        expected = 1 / (1 + 10 ** ((opponent_rating - player_rating) / 400))
        new_rating = round(player_rating + k_factor * (result - expected))
        return max(0, min(4000, new_rating))

    @staticmethod
    def update_user_stats(user, result):
        """유저 통계 업데이트 (저장하지 않음, 호출자가 save 필요)

        Args:
            user (User): 유저 인스턴스
            result (str): 'win', 'loss', 'draw'
        """
        user.games_played += 1
        if result == "win":
            user.games_won += 1
        elif result == "loss":
            user.games_lost += 1
        elif result == "draw":
            user.games_draw += 1

    @staticmethod
    def update_ratings_and_stats(white_player, black_player, game_result):
        """게임 종료 후 양쪽 플레이어 레이팅 및 통계 업데이트

        Args:
            white_player (User): 백 플레이어
            black_player (User): 흑 플레이어
            game_result (str): 게임 결과 ('white_win', 'black_win', 'draw' 등)

        Note: 이 메서드는 save()하지 않음. 호출자가 transaction.atomic으로 묶어서 처리
        """
        if game_result in ["white_win", "checkmate_white", "timeout_black", "resignation_black"]:
            white_result = "win"
            black_result = "loss"
            white_score = 1.0
            black_score = 0.0
        elif game_result in [
            "black_win",
            "checkmate_black",
            "timeout_white",
            "resignation_white",
        ]:
            white_result = "loss"
            black_result = "win"
            white_score = 0.0
            black_score = 1.0
        else:
            white_result = "draw"
            black_result = "draw"
            white_score = 0.5
            black_score = 0.5

        RatingService.update_user_stats(white_player, white_result)
        RatingService.update_user_stats(black_player, black_result)

        white_player.rating = RatingService.calculate_new_rating(
            white_player.rating, black_player.rating, white_score
        )
        black_player.rating = RatingService.calculate_new_rating(
            black_player.rating, white_player.rating, black_score
        )
