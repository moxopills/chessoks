from rest_framework import serializers

from apps.accounts.models import DirectMessage, GuestbookEntry
from apps.accounts.serializers.user_serializer import PublicUserSerializer


class GuestbookEntrySerializer(serializers.ModelSerializer):
    author = PublicUserSerializer(read_only=True)

    class Meta:
        model = GuestbookEntry
        fields = ("id", "author", "message", "created_at")


class GuestbookCreateSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=200)


class DirectMessageSerializer(serializers.ModelSerializer):
    sender = PublicUserSerializer(read_only=True)

    class Meta:
        model = DirectMessage
        fields = ("id", "sender", "message", "created_at")


class DirectMessageCreateSerializer(serializers.Serializer):
    message = serializers.CharField(max_length=500)


class DirectMessageThreadSerializer(serializers.Serializer):
    id = serializers.IntegerField()
    other_user = PublicUserSerializer()
    last_message = serializers.CharField(allow_blank=True, allow_null=True)
    last_message_at = serializers.DateTimeField(allow_null=True)
