from rest_framework import serializers


class RoomReadyRequestSerializer(serializers.Serializer):
    ready = serializers.BooleanField(required=False, default=True)


class RoomReadyResponseSerializer(serializers.Serializer):
    room_id = serializers.IntegerField(read_only=True)
    status = serializers.CharField(read_only=True)
    host_ready = serializers.BooleanField(read_only=True)
    guest_ready = serializers.BooleanField(read_only=True)
    host_start_confirmed = serializers.BooleanField(read_only=True)
    guest_start_confirmed = serializers.BooleanField(read_only=True)


class RoomStartConfirmResponseSerializer(serializers.Serializer):
    room_id = serializers.IntegerField(read_only=True)
    status = serializers.CharField(read_only=True)
    game_id = serializers.IntegerField(read_only=True, allow_null=True)
    host_start_confirmed = serializers.BooleanField(read_only=True)
    guest_start_confirmed = serializers.BooleanField(read_only=True)
