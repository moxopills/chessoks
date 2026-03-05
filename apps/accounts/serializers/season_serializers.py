from __future__ import annotations

from rest_framework import serializers

from apps.accounts.models import Season, SeasonReward, SeasonStat


class SeasonSerializer(serializers.ModelSerializer):
    days_left = serializers.SerializerMethodField()

    class Meta:
        model = Season
        fields = [
            "id",
            "name",
            "start_date",
            "end_date",
            "is_active",
            "is_finalized",
            "days_left",
        ]

    def get_days_left(self, obj: Season) -> int:
        from django.utils import timezone

        today = timezone.localdate()
        if obj.end_date < today:
            return 0
        return (obj.end_date - today).days


class SeasonLeaderboardEntrySerializer(serializers.ModelSerializer):
    user_id = serializers.IntegerField(source="user.id", read_only=True)
    nickname = serializers.CharField(source="user.nickname", read_only=True)
    avatar_url = serializers.CharField(source="user.avatar_url", read_only=True)
    rank_tier = serializers.CharField(source="user.stats.rank_tier", read_only=True)
    win_rate = serializers.FloatField(read_only=True)
    rank = serializers.IntegerField(read_only=True)

    class Meta:
        model = SeasonStat
        fields = [
            "rank",
            "user_id",
            "nickname",
            "avatar_url",
            "rank_tier",
            "rating",
            "peak_rating",
            "games_played",
            "wins",
            "losses",
            "draws",
            "win_rate",
        ]


class SeasonRewardSerializer(serializers.ModelSerializer):
    reward_type_label = serializers.CharField(source="get_reward_type_display", read_only=True)

    class Meta:
        model = SeasonReward
        fields = [
            "id",
            "rank_min",
            "rank_max",
            "reward_type",
            "reward_type_label",
            "reward_value",
        ]
