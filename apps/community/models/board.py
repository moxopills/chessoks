from django.conf import settings
from django.db import models


class BoardCategory(models.Model):
    code = models.CharField(max_length=24, unique=True)
    title = models.CharField(max_length=40)
    description = models.CharField(max_length=120, blank=True, default="")
    sort_order = models.PositiveSmallIntegerField(default=0)
    is_enabled = models.BooleanField(default=True)
    is_recruitment = models.BooleanField(default=False)

    class Meta:
        db_table = "board_categories"
        ordering = ["sort_order", "id"]

    def __str__(self):
        return self.title


class BoardPost(models.Model):
    category = models.ForeignKey(BoardCategory, on_delete=models.PROTECT, related_name="posts")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="board_posts",
    )
    title = models.CharField(max_length=120)
    content = models.TextField()
    is_pinned = models.BooleanField(default=False)
    is_blinded = models.BooleanField(default=False)
    view_count = models.PositiveIntegerField(default=0)
    comment_count = models.PositiveIntegerField(default=0)
    last_commented_at = models.DateTimeField(null=True, blank=True)
    guild_name = models.CharField(max_length=40, blank=True, default="")
    recruitment_slots = models.PositiveSmallIntegerField(null=True, blank=True)
    minimum_rating = models.PositiveIntegerField(null=True, blank=True)
    active_time_band = models.CharField(max_length=80, blank=True, default="")
    join_policy_text = models.CharField(max_length=40, blank=True, default="")
    contact_method = models.CharField(max_length=80, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "board_posts"
        ordering = ["-is_pinned", "-created_at"]
        indexes = [
            models.Index(fields=["category", "-created_at"], name="board_post_cat_created_ix"),
            models.Index(fields=["category", "-view_count"], name="board_post_category_views_idx"),
            models.Index(fields=["author", "-created_at"], name="board_post_author_created_idx"),
        ]


class BoardComment(models.Model):
    post = models.ForeignKey(BoardPost, on_delete=models.CASCADE, related_name="comments")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="board_comments",
    )
    content = models.CharField(max_length=500)
    is_blinded = models.BooleanField(default=False)
    like_count = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "board_comments"
        ordering = ["created_at"]
        indexes = [
            models.Index(fields=["post", "created_at"], name="board_comment_post_created_idx"),
        ]


class BoardCommentLike(models.Model):
    comment = models.ForeignKey(
        BoardComment,
        on_delete=models.CASCADE,
        related_name="likes",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="board_comment_likes",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "board_comment_likes"
        constraints = [
            models.UniqueConstraint(
                fields=["comment", "user"],
                name="uniq_board_comment_like",
            ),
        ]


class BoardReport(models.Model):
    class TargetType(models.TextChoices):
        POST = "post", "게시글"
        COMMENT = "comment", "댓글"

    class Status(models.TextChoices):
        PENDING = "pending", "대기"
        RESOLVED = "resolved", "처리"

    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="board_reports",
    )
    target_type = models.CharField(max_length=16, choices=TargetType.choices)
    post = models.ForeignKey(
        BoardPost,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="reports",
    )
    comment = models.ForeignKey(
        BoardComment,
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="reports",
    )
    reason = models.CharField(max_length=200)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "board_reports"
        indexes = [
            models.Index(fields=["status", "-created_at"], name="board_report_stat_created_ix"),
        ]
