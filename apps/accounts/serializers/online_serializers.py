from rest_framework import serializers


class OnlineStatusSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    online = serializers.BooleanField(read_only=True)


class OnlineStatusListSerializer(serializers.Serializer):
    results = OnlineStatusSerializer(many=True, read_only=True)
