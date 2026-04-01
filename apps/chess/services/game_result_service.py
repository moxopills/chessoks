from __future__ import annotations

import logging

from django.core.cache import cache
from django.db import transaction
from django.utils import timezone

from apps.accounts.models import UserStats
from apps.accounts.models.skin import SkinPointLog
from apps.accounts.services.ranking_service import RankingService
from apps.accounts.services.user_stats_service import UserStatsService
from apps.chess.models import Game
from apps.chess.services.rating_service import RatingService
from apps.notifications.services import NotificationService


class GameResultService:
    logger = logging.getLogger(__name__)
    TIER_ORDER = {
        "Unranked": -1,
        "Beginner": 0,
        "Junior": 1,
        "Intermediate": 2,
        "Advanced": 3,
        "Expert": 4,
        "Master": 5,
    }

    @staticmethod
    def apply_post_game_updates(game: Game) -> dict | None:
        if game.room.room_type.startswith("ai_"):
            return None
        if GameResultService.is_competitive_room(game.room.room_type):
            rating_info = GameResultService._apply_rating_update(game)
            GameResultService._schedule_achievement_sync(game)
            return rating_info
        GameResultService._apply_stats_only(game)
        GameResultService._schedule_achievement_sync(game)
        return None

    @staticmethod
    def is_competitive_room(room_type: str) -> bool:
        return room_type == "quick"

    @staticmethod
    def notify_game_end(game: Game, rating_info: dict | None) -> None:
        reason = GameResultService.result_reason(game.result)
        ai_room = game.room.room_type.startswith("ai_")
        competitive_room = GameResultService.is_competitive_room(game.room.room_type)

        for color, player in (
            (Game.Color.WHITE, game.white_player),
            (Game.Color.BLACK, game.black_player),
        ):
            cache.delete(f"user_profile_{player.id}")
            outcome = GameResultService.result_outcome(game.result, color)
            outcome_text = {"win": "승리", "loss": "패배", "draw": "무승부"}[outcome]
            message = (
                f"{reason}로 {outcome_text}했습니다." if reason else f"{outcome_text}했습니다."
            )
            NotificationService.create_notification(
                user=player,
                type="game_result",
                title="게임 종료",
                message=message,
                payload={"game_id": game.id, "result": game.result, "outcome": outcome},
            )

            if rating_info:
                rating_before = rating_info[color]["before"]
                rating_after = rating_info[color]["after"]
                delta = rating_after - rating_before
                NotificationService.create_notification(
                    user=player,
                    type="rating_change",
                    title="레이팅 변동",
                    message=f"{rating_before} -> {rating_after} ({delta:+d})",
                    payload={
                        "game_id": game.id,
                        "before": rating_before,
                        "after": rating_after,
                        "delta": delta,
                    },
                )

                tier_before = rating_info[color]["tier_before"]
                tier_after = rating_info[color]["tier_after"]
                if GameResultService._tier_rank(tier_after) > GameResultService._tier_rank(
                    tier_before
                ):
                    NotificationService.create_notification(
                        user=player,
                        type="tier_promotion",
                        title="티어 승격",
                        message=f"{tier_after} 티어로 승격했습니다.",
                        payload={"before": tier_before, "after": tier_after, "game_id": game.id},
                    )

            if competitive_room:
                stats = (
                    UserStats.objects.filter(user=player).only("competitive_games_played").first()
                )
                if stats and stats.competitive_games_played < 5:
                    NotificationService.create_notification(
                        user=player,
                        type="placement_progress",
                        title="배치전 진행",
                        message=f"배치 진행: {stats.competitive_games_played}/5",
                        payload={"game_id": game.id, "played": stats.competitive_games_played},
                    )

        if ai_room:
            GameResultService.logger.info(
                "AI game end game=%s result=%s white=%s black=%s",
                game.id,
                game.result,
                game.white_player_id,
                game.black_player_id,
            )

        from apps.chess.utils import broadcast_room_update

        room = game.room
        room.status = "finished"
        room.finished_at = game.finished_at or timezone.now()
        room.save(update_fields=["status", "finished_at"])
        broadcast_room_update(room)

    @staticmethod
    def result_outcome(result: str, player_color: str) -> str:
        white_win = {
            Game.Status.WHITE_WIN,
            Game.Status.CHECKMATE_WHITE,
            Game.Status.TIMEOUT_BLACK,
            Game.Status.RESIGNATION_BLACK,
        }
        black_win = {
            Game.Status.BLACK_WIN,
            Game.Status.CHECKMATE_BLACK,
            Game.Status.TIMEOUT_WHITE,
            Game.Status.RESIGNATION_WHITE,
        }
        if result in white_win:
            return "win" if player_color == Game.Color.WHITE else "loss"
        if result in black_win:
            return "loss" if player_color == Game.Color.WHITE else "win"
        return "draw"

    @staticmethod
    def result_reason(result: str) -> str:
        reasons = {
            Game.Status.CHECKMATE_WHITE: "체크메이트",
            Game.Status.CHECKMATE_BLACK: "체크메이트",
            Game.Status.TIMEOUT_WHITE: "시간 초과",
            Game.Status.TIMEOUT_BLACK: "시간 초과",
            Game.Status.RESIGNATION_WHITE: "기권",
            Game.Status.RESIGNATION_BLACK: "기권",
            Game.Status.STALEMATE: "스테일메이트",
            Game.Status.DRAW_INSUFFICIENT: "기물 부족",
            Game.Status.DRAW_REPETITION: "삼중 반복",
            Game.Status.DRAW_FIFTY_MOVE: "50수 규칙",
            Game.Status.DRAW_AGREEMENT: "합의 무승부",
        }
        return reasons.get(result, "")

    @staticmethod
    def _apply_stats_only(game: Game) -> None:
        if game.white_player.is_guest or game.black_player.is_guest:
            return
        white_stats, _ = UserStats.objects.get_or_create(user=game.white_player)
        black_stats, _ = UserStats.objects.get_or_create(user=game.black_player)
        RatingService.update_stats_only(white_stats, black_stats, game.result)
        white_delta, black_delta = GameResultService._apply_style_points(
            white_stats, black_stats, game.result
        )
        white_stats.save()
        black_stats.save()
        GameResultService._record_style_point_log(
            game.id, white_stats, white_delta, black_stats, black_delta
        )
        RankingService.invalidate_leaderboard_cache()

    @staticmethod
    def _apply_rating_update(game: Game) -> dict | None:
        if game.white_player.is_guest or game.black_player.is_guest:
            return None
        white_stats, _ = UserStats.objects.get_or_create(user=game.white_player)
        black_stats, _ = UserStats.objects.get_or_create(user=game.black_player)

        white_before = white_stats.rating
        black_before = black_stats.rating
        white_tier_before = UserStatsService.get_rank_tier(white_stats)
        black_tier_before = UserStatsService.get_rank_tier(black_stats)

        RatingService.update_ratings_and_stats(white_stats, black_stats, game.result)
        white_delta, black_delta = GameResultService._apply_style_points(
            white_stats, black_stats, game.result
        )
        white_stats.save()
        black_stats.save()
        GameResultService._record_style_point_log(
            game.id, white_stats, white_delta, black_stats, black_delta
        )
        try:
            from apps.accounts.services import SeasonService

            SeasonService.update_after_competitive_game(
                white_user_id=game.white_player_id,
                black_user_id=game.black_player_id,
                game_result=game.result,
            )
        except Exception as exc:
            GameResultService.logger.exception("Season update failed for game %s: %s", game.id, exc)
        RankingService.invalidate_leaderboard_cache()
        return {
            "white": {
                "before": white_before,
                "after": white_stats.rating,
                "tier_before": white_tier_before,
                "tier_after": UserStatsService.get_rank_tier(white_stats),
            },
            "black": {
                "before": black_before,
                "after": black_stats.rating,
                "tier_before": black_tier_before,
                "tier_after": UserStatsService.get_rank_tier(black_stats),
            },
        }

    @staticmethod
    def _schedule_achievement_sync(game: Game) -> None:
        user_ids = [
            player_id
            for player_id, is_guest in (
                (game.white_player_id, getattr(game.white_player, "is_guest", False)),
                (game.black_player_id, getattr(game.black_player, "is_guest", False)),
            )
            if player_id and not is_guest
        ]
        if not user_ids:
            return

        def _sync():
            try:
                from apps.accounts.services import AchievementService

                AchievementService.sync_rewards_for_users(user_ids)
            except Exception:
                GameResultService.logger.exception(
                    "Achievement sync failed after game result update game=%s users=%s",
                    game.id,
                    user_ids,
                )

        transaction.on_commit(_sync)

    @staticmethod
    def _apply_style_points(
        white_stats: UserStats, black_stats: UserStats, result: str
    ) -> tuple[int, int]:
        white_delta = 10
        black_delta = 10
        white_stats.style_points = (white_stats.style_points or 0) + 10
        black_stats.style_points = (black_stats.style_points or 0) + 10

        white_win = {
            Game.Status.WHITE_WIN,
            Game.Status.CHECKMATE_WHITE,
            Game.Status.TIMEOUT_BLACK,
            Game.Status.RESIGNATION_BLACK,
        }
        black_win = {
            Game.Status.BLACK_WIN,
            Game.Status.CHECKMATE_BLACK,
            Game.Status.TIMEOUT_WHITE,
            Game.Status.RESIGNATION_WHITE,
        }
        draw_set = {
            Game.Status.DRAW,
            Game.Status.STALEMATE,
            Game.Status.DRAW_AGREEMENT,
            Game.Status.DRAW_REPETITION,
            Game.Status.DRAW_FIFTY_MOVE,
            Game.Status.DRAW_INSUFFICIENT,
        }

        if result in white_win:
            white_stats.style_points += 5
            white_delta += 5
        elif result in black_win:
            black_stats.style_points += 5
            black_delta += 5
        elif result in draw_set:
            white_stats.style_points += 2
            black_stats.style_points += 2
            white_delta += 2
            black_delta += 2
        return white_delta, black_delta

    @staticmethod
    def _record_style_point_log(
        game_id: int,
        white_stats: UserStats,
        white_delta: int,
        black_stats: UserStats,
        black_delta: int,
    ) -> None:
        white_reason = SkinPointLog.Reason.GAME_DRAW
        black_reason = SkinPointLog.Reason.GAME_DRAW
        if white_delta > black_delta:
            white_reason = SkinPointLog.Reason.GAME_WIN
            black_reason = SkinPointLog.Reason.GAME_LOSS
        elif black_delta > white_delta:
            white_reason = SkinPointLog.Reason.GAME_LOSS
            black_reason = SkinPointLog.Reason.GAME_WIN

        now = timezone.now()
        SkinPointLog.objects.bulk_create(
            [
                SkinPointLog(
                    user_id=white_stats.user_id,
                    amount=white_delta,
                    balance=white_stats.style_points,
                    reason=white_reason,
                    reference_id=str(game_id),
                    created_at=now,
                ),
                SkinPointLog(
                    user_id=black_stats.user_id,
                    amount=black_delta,
                    balance=black_stats.style_points,
                    reason=black_reason,
                    reference_id=str(game_id),
                    created_at=now,
                ),
            ]
        )

    @staticmethod
    def _tier_rank(tier: str) -> int:
        return GameResultService.TIER_ORDER.get(tier, 0)
