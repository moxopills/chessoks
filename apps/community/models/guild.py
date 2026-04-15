from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Guild(models.Model):
    class JoinPolicy(models.TextChoices):
        OPEN = "open", "자유 가입"
        APPROVAL = "approval", "승인제"

    owner = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="owned_guilds",
    )
    name = models.CharField(max_length=40, unique=True)
    slug = models.SlugField(max_length=48, unique=True, blank=True)
    avatar_url = models.URLField(max_length=500, blank=True, null=True)
    description = models.TextField(blank=True)
    notice = models.CharField(max_length=200, blank=True, default="")
    join_policy = models.CharField(
        max_length=16,
        choices=JoinPolicy.choices,
        default=JoinPolicy.APPROVAL,
    )
    min_rating = models.IntegerField(default=0)
    active_hours = models.CharField(max_length=80, blank=True, default="")
    contact_channel = models.CharField(max_length=80, blank=True, default="")
    team_rating = models.IntegerField(default=1200)
    member_count = models.PositiveIntegerField(default=1)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "guilds"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["slug"], name="guild_slug_idx"),
            models.Index(fields=["join_policy", "-created_at"], name="guild_policy_created_idx"),
            models.Index(fields=["-team_rating", "-member_count"], name="guild_rating_members_idx"),
        ]

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.name, allow_unicode=True)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name


class GuildMember(models.Model):
    class Role(models.TextChoices):
        LEADER = "leader", "길드장"
        VICE = "vice", "부길드장"
        MANAGER = "manager", "운영진"
        MEMBER = "member", "일반"

    guild = models.ForeignKey(Guild, on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="guild_memberships",
    )
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.MEMBER)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "guild_members"
        constraints = [
            models.UniqueConstraint(fields=["guild", "user"], name="uniq_guild_member"),
        ]
        indexes = [
            models.Index(fields=["guild", "role"], name="guild_member_role_idx"),
            models.Index(fields=["user", "-joined_at"], name="guild_member_user_joined_idx"),
        ]

    def __str__(self):
        return f"{self.guild_id}:{self.user_id}:{self.role}"


class GuildJoinRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "대기"
        APPROVED = "approved", "승인"
        REJECTED = "rejected", "거절"

    guild = models.ForeignKey(Guild, on_delete=models.CASCADE, related_name="join_requests")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="guild_join_requests",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    message = models.CharField(max_length=200, blank=True, default="")
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_guild_join_requests",
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "guild_join_requests"
        indexes = [
            models.Index(fields=["guild", "status", "-created_at"], name="guild_join_status_idx"),
            models.Index(
                fields=["user", "status", "-created_at"], name="guild_join_user_status_idx"
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["guild", "user"],
                condition=models.Q(status="pending"),
                name="uniq_pending_guild_join_request",
            )
        ]


class GuildChatMessage(models.Model):
    guild = models.ForeignKey(Guild, on_delete=models.CASCADE, related_name="chat_messages")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="guild_chat_messages",
    )
    content = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "guild_chat_messages"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["guild", "-created_at"], name="guild_chat_created_idx"),
        ]


class GuildNotice(models.Model):
    guild = models.ForeignKey(Guild, on_delete=models.CASCADE, related_name="notice_history")
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="guild_notices_authored",
    )
    content = models.CharField(max_length=200)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "guild_notices"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["guild", "-created_at"], name="guild_notice_created_idx"),
        ]


class GuildAuditLog(models.Model):
    guild = models.ForeignKey(Guild, on_delete=models.CASCADE, related_name="audit_logs")
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="guild_audit_actions",
    )
    target_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="guild_audit_targets",
    )
    action = models.CharField(max_length=32)
    detail = models.CharField(max_length=200, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "guild_audit_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["guild", "-created_at"], name="guild_audit_created_idx"),
            models.Index(fields=["action", "-created_at"], name="guild_audit_action_idx"),
        ]
