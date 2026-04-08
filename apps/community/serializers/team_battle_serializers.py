from rest_framework import serializers

from apps.community.models import TeamBattleMatch, TeamBattleParticipant, TeamBattleRound

from .common import PlainUserSerializer


class TeamBattleCreateSerializer(serializers.Serializer):
    battle_type = serializers.ChoiceField(choices=TeamBattleMatch.BattleType.choices)
    party_id = serializers.IntegerField(required=False, allow_null=True)
    guild_id = serializers.IntegerField(required=False, allow_null=True)

    def validate(self, attrs):
        battle_type = attrs.get("battle_type")
        if battle_type == TeamBattleMatch.BattleType.PARTY and not attrs.get("party_id"):
            raise serializers.ValidationError({"party_id": ["단체전에는 파티 ID가 필요합니다."]})
        if battle_type == TeamBattleMatch.BattleType.GUILD and not attrs.get("guild_id"):
            raise serializers.ValidationError({"guild_id": ["길드전에는 길드 ID가 필요합니다."]})
        return attrs


class TeamBattleMatchSerializer(serializers.ModelSerializer):
    host_party_id = serializers.IntegerField(read_only=True)
    guest_party_id = serializers.IntegerField(read_only=True)
    host_guild_id = serializers.IntegerField(read_only=True)
    guest_guild_id = serializers.IntegerField(read_only=True)

    class Meta:
        model = TeamBattleMatch
        fields = [
            "id",
            "battle_type",
            "status",
            "host_party_id",
            "guest_party_id",
            "host_guild_id",
            "guest_guild_id",
            "host_remaining",
            "guest_remaining",
            "winner_side",
            "scheduled_at",
            "started_at",
            "ended_at",
            "created_at",
        ]


class TeamBattleParticipantSerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = TeamBattleParticipant
        fields = ["id", "side", "order", "wins", "is_eliminated", "user"]


class TeamBattleRoundSerializer(serializers.ModelSerializer):
    host_participant = TeamBattleParticipantSerializer(read_only=True)
    guest_participant = TeamBattleParticipantSerializer(read_only=True)
    game_id = serializers.IntegerField(read_only=True)
    game_room_id = serializers.IntegerField(source="game.room_id", read_only=True)

    class Meta:
        model = TeamBattleRound
        fields = [
            "id",
            "round_number",
            "status",
            "result",
            "game_id",
            "game_room_id",
            "created_at",
            "started_at",
            "ended_at",
            "host_participant",
            "guest_participant",
        ]


class TeamBattleMatchDetailSerializer(TeamBattleMatchSerializer):
    participants = TeamBattleParticipantSerializer(many=True, read_only=True)
    rounds = TeamBattleRoundSerializer(many=True, read_only=True)

    class Meta:
        model = TeamBattleMatch
        fields = TeamBattleMatchSerializer.Meta.fields + ["participants", "rounds"]


class TeamBattleJoinSerializer(serializers.Serializer):
    party_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)
    guild_id = serializers.IntegerField(required=False, allow_null=True, min_value=1)

    def validate(self, attrs):
        if not attrs.get("party_id") and not attrs.get("guild_id"):
            raise serializers.ValidationError("파티 ID 또는 길드 ID 중 하나는 필요합니다.")
        return attrs


class TeamBattleRoundResultSerializer(serializers.Serializer):
    result = serializers.ChoiceField(choices=TeamBattleRound.Result.choices)
