from rest_framework import serializers

from apps.community.models import Party, PartyChatMessage, PartyInvite, PartyMember

from .common import PlainUserSerializer


class PartyCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=60)
    description = serializers.CharField(max_length=200, required=False, allow_blank=True)


class PartyMemberSerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = PartyMember
        fields = ["user", "slot", "is_ready", "joined_at"]


class PartySerializer(serializers.ModelSerializer):
    leader = PlainUserSerializer(read_only=True)

    class Meta:
        model = Party
        fields = [
            "id",
            "title",
            "description",
            "status",
            "max_members",
            "lineup_locked",
            "created_at",
            "leader",
        ]


class PartyDetailSerializer(PartySerializer):
    members = PartyMemberSerializer(many=True, read_only=True)

    class Meta(PartySerializer.Meta):
        fields = PartySerializer.Meta.fields + ["members"]


class PartyInviteCreateSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(min_value=1)


class PartyInviteRespondSerializer(serializers.Serializer):
    accept = serializers.BooleanField()


class PartyInviteSerializer(serializers.ModelSerializer):
    from_user = PlainUserSerializer(read_only=True)
    to_user = PlainUserSerializer(read_only=True)
    party_id = serializers.IntegerField(read_only=True)
    party_title = serializers.CharField(source="party.title", read_only=True)

    class Meta:
        model = PartyInvite
        fields = [
            "id",
            "status",
            "created_at",
            "responded_at",
            "party_id",
            "party_title",
            "from_user",
            "to_user",
        ]


class PartyMemberReadySerializer(serializers.Serializer):
    ready = serializers.BooleanField()


class PartySlotSerializer(serializers.Serializer):
    user_id = serializers.IntegerField(min_value=1)
    slot = serializers.IntegerField(min_value=1, max_value=3)


class PartyChatCreateSerializer(serializers.Serializer):
    content = serializers.CharField(max_length=500)


class PartyChatMessageSerializer(serializers.ModelSerializer):
    user = PlainUserSerializer(read_only=True)

    class Meta:
        model = PartyChatMessage
        fields = ["id", "content", "created_at", "user"]


class PartyLockSerializer(serializers.Serializer):
    locked = serializers.BooleanField()
