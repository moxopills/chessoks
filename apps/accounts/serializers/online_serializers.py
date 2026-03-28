from rest_framework import serializers


class OnlineStatusSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    online = serializers.BooleanField(read_only=True)
    status = serializers.CharField(read_only=True)
    status_label = serializers.CharField(read_only=True)
    room_id = serializers.IntegerField(read_only=True, allow_null=True)
    game_id = serializers.IntegerField(read_only=True, allow_null=True)


class PresenceUpdateSerializer(serializers.Serializer):
    status = serializers.ChoiceField(choices=["online", "room_waiting", "puzzle"])
    active = serializers.BooleanField(required=False, default=True)
    room_id = serializers.IntegerField(required=False, allow_null=True)
    game_id = serializers.IntegerField(required=False, allow_null=True)
    scope_id = serializers.CharField(required=False, allow_blank=True, max_length=80)


class OnlineStatusListSerializer(serializers.Serializer):
    results = OnlineStatusSerializer(many=True, read_only=True)
