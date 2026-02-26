from rest_framework import serializers


class NotificationSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    type = serializers.CharField(read_only=True)
    title = serializers.CharField(read_only=True)
    message = serializers.CharField(read_only=True)
    payload = serializers.JSONField(read_only=True)
    is_read = serializers.BooleanField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class NotificationListSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)
    results = NotificationSerializer(many=True, read_only=True)


class NotificationReadSerializer(serializers.Serializer):
    ids = serializers.ListField(child=serializers.IntegerField(min_value=1), allow_empty=False)


class NotificationUnreadSerializer(serializers.Serializer):
    count = serializers.IntegerField(read_only=True)


class WebPushSubscribeSerializer(serializers.Serializer):
    endpoint = serializers.CharField(max_length=4096)
    p256dh = serializers.CharField(max_length=1024)
    auth = serializers.CharField(max_length=1024)
    user_agent = serializers.CharField(required=False, allow_blank=True, max_length=1024)


class WebPushUnsubscribeSerializer(serializers.Serializer):
    endpoint = serializers.CharField(required=False, allow_blank=True, max_length=4096)
