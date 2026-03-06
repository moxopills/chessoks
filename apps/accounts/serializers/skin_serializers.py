from rest_framework import serializers


class SkinSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)
    skin_type = serializers.CharField(read_only=True)
    price = serializers.IntegerField(read_only=True)
    css_class = serializers.CharField(read_only=True)
    preview_image = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    is_default = serializers.BooleanField(read_only=True)
    is_active = serializers.BooleanField(read_only=True)
    sort_order = serializers.IntegerField(read_only=True)
    owned = serializers.BooleanField(read_only=True)
    selected = serializers.BooleanField(read_only=True)


class SkinListResponseSerializer(serializers.Serializer):
    points = serializers.IntegerField(read_only=True)
    board = SkinSerializer(many=True, read_only=True)
    pieces = SkinSerializer(many=True, read_only=True)


class SkinSelectRequestSerializer(serializers.Serializer):
    skin_id = serializers.IntegerField(required=False)


class SkinPointLogSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    amount = serializers.IntegerField(read_only=True)
    balance = serializers.IntegerField(read_only=True)
    reason = serializers.CharField(read_only=True)
    reason_label = serializers.CharField(read_only=True)
    reference_id = serializers.CharField(read_only=True)
    created_at = serializers.DateTimeField(read_only=True)


class SkinPointHistoryResponseSerializer(serializers.Serializer):
    results = SkinPointLogSerializer(many=True, read_only=True)
