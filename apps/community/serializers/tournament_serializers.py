from rest_framework import serializers

from apps.community.models import Tournament, TournamentEntry

from .common import PlainUserSerializer


class TournamentCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=80)
    description = serializers.CharField(required=False, allow_blank=True)
    max_participants = serializers.IntegerField(min_value=4, max_value=64)
    minimum_rating = serializers.IntegerField(
        min_value=0, max_value=4000, required=False, default=0
    )
    maximum_rating = serializers.IntegerField(
        min_value=0, max_value=4000, required=False, default=4000
    )
    start_at = serializers.DateTimeField()


class TournamentSerializer(serializers.ModelSerializer):
    entry_count = serializers.SerializerMethodField()
    is_registered = serializers.SerializerMethodField()

    def get_entry_count(self, obj):
        return getattr(obj, "entry_count", 0)

    def get_is_registered(self, obj):
        return bool(getattr(obj, "is_registered", False))

    class Meta:
        model = Tournament
        fields = [
            "id",
            "title",
            "slug",
            "description",
            "status",
            "max_participants",
            "minimum_rating",
            "maximum_rating",
            "winner_title",
            "entry_count",
            "is_registered",
            "start_at",
            "end_at",
            "created_at",
        ]


class TournamentEntrySerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = TournamentEntry
        fields = ["id", "status", "seed", "joined_at", "user"]


class TournamentRegisterSerializer(serializers.Serializer):
    tournament_id = serializers.IntegerField(min_value=1)
