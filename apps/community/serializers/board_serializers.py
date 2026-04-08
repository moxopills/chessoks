from rest_framework import serializers

from apps.community.models import BoardCategory, BoardComment, BoardPost

from .common import PlainUserSerializer


class BoardCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = BoardCategory
        fields = ["id", "code", "title", "description", "sort_order", "is_recruitment"]


class BoardPostCreateSerializer(serializers.Serializer):
    category_code = serializers.CharField(max_length=24)
    title = serializers.CharField(max_length=120)
    content = serializers.CharField()
    guild_name = serializers.CharField(max_length=40, required=False, allow_blank=True)
    recruitment_slots = serializers.IntegerField(
        required=False, min_value=1, max_value=99, allow_null=True
    )
    minimum_rating = serializers.IntegerField(
        required=False, min_value=0, max_value=4000, allow_null=True
    )
    active_time_band = serializers.CharField(max_length=80, required=False, allow_blank=True)
    join_policy_text = serializers.CharField(max_length=40, required=False, allow_blank=True)
    contact_method = serializers.CharField(max_length=80, required=False, allow_blank=True)


class BoardCommentSerializer(serializers.ModelSerializer):
    author = PlainUserSerializer(read_only=True)

    class Meta:
        model = BoardComment
        fields = ["id", "content", "is_blinded", "created_at", "author"]


class BoardPostSerializer(serializers.ModelSerializer):
    author = PlainUserSerializer(read_only=True)
    category = BoardCategorySerializer(read_only=True)
    comments = BoardCommentSerializer(many=True, read_only=True)

    class Meta:
        model = BoardPost
        fields = [
            "id",
            "title",
            "content",
            "is_pinned",
            "is_blinded",
            "view_count",
            "comment_count",
            "guild_name",
            "recruitment_slots",
            "minimum_rating",
            "active_time_band",
            "join_policy_text",
            "contact_method",
            "created_at",
            "updated_at",
            "author",
            "category",
            "comments",
        ]


class BoardPostSummarySerializer(serializers.ModelSerializer):
    author = PlainUserSerializer(read_only=True)
    category = BoardCategorySerializer(read_only=True)

    class Meta:
        model = BoardPost
        fields = [
            "id",
            "title",
            "is_pinned",
            "is_blinded",
            "view_count",
            "comment_count",
            "guild_name",
            "created_at",
            "author",
            "category",
            "content",
        ]


class BoardCommentCreateSerializer(serializers.Serializer):
    content = serializers.CharField(max_length=500)


class BoardReportCreateSerializer(serializers.Serializer):
    target_type = serializers.ChoiceField(choices=[("post", "post"), ("comment", "comment")])
    post_id = serializers.IntegerField(required=False, allow_null=True)
    comment_id = serializers.IntegerField(required=False, allow_null=True)
    reason = serializers.CharField(max_length=200)
