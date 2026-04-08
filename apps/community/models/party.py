from django.conf import settings
from django.db import models


class Party(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "모집중"
        READY = "ready", "준비완료"
        QUEUED = "queued", "매칭대기"
        BATTLING = "battling", "대전중"
        CLOSED = "closed", "종료"

    leader = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="led_parties",
    )
    title = models.CharField(max_length=60)
    description = models.CharField(max_length=200, blank=True, default="")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    max_members = models.PositiveSmallIntegerField(default=3)
    lineup_locked = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "parties"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "-updated_at"], name="party_status_updated_idx"),
            models.Index(fields=["leader", "-created_at"], name="party_leader_created_idx"),
        ]


class PartyMember(models.Model):
    party = models.ForeignKey(Party, on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="party_memberships",
    )
    slot = models.PositiveSmallIntegerField(null=True, blank=True)
    is_ready = models.BooleanField(default=False)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "party_members"
        constraints = [
            models.UniqueConstraint(fields=["party", "user"], name="uniq_party_member"),
            models.UniqueConstraint(
                fields=["party", "slot"],
                condition=models.Q(slot__isnull=False),
                name="uniq_party_slot",
            ),
        ]
        indexes = [
            models.Index(fields=["party", "is_ready"], name="party_member_ready_idx"),
            models.Index(fields=["user", "-joined_at"], name="party_member_user_joined_idx"),
        ]


class PartyInvite(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "대기"
        ACCEPTED = "accepted", "수락"
        DECLINED = "declined", "거절"
        EXPIRED = "expired", "만료"

    party = models.ForeignKey(Party, on_delete=models.CASCADE, related_name="invites")
    from_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="party_invites_sent",
    )
    to_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="party_invites_received",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    created_at = models.DateTimeField(auto_now_add=True)
    responded_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "party_invites"
        indexes = [
            models.Index(fields=["to_user", "status", "-created_at"], name="party_invite_to_idx"),
            models.Index(fields=["party", "status", "-created_at"], name="party_invite_party_idx"),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["party", "to_user"],
                condition=models.Q(status="pending"),
                name="uniq_pending_party_invite",
            )
        ]


class PartyChatMessage(models.Model):
    party = models.ForeignKey(Party, on_delete=models.CASCADE, related_name="chat_messages")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="party_chat_messages",
    )
    content = models.CharField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "party_chat_messages"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["party", "-created_at"], name="party_chat_created_idx"),
        ]


class TeamBattleMatch(models.Model):
    class BattleType(models.TextChoices):
        PARTY = "party", "단체전"
        GUILD = "guild", "길드전"

    class Status(models.TextChoices):
        WAITING = "waiting", "대기"
        LIVE = "live", "진행중"
        FINISHED = "finished", "종료"
        CANCELLED = "cancelled", "취소"

    battle_type = models.CharField(max_length=16, choices=BattleType.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.WAITING)
    host_party = models.ForeignKey(
        Party, null=True, blank=True, on_delete=models.CASCADE, related_name="host_team_battles"
    )
    guest_party = models.ForeignKey(
        Party, null=True, blank=True, on_delete=models.CASCADE, related_name="guest_team_battles"
    )
    host_guild = models.ForeignKey(
        "community.Guild",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="host_guild_battles",
    )
    guest_guild = models.ForeignKey(
        "community.Guild",
        null=True,
        blank=True,
        on_delete=models.CASCADE,
        related_name="guest_guild_battles",
    )
    host_remaining = models.PositiveSmallIntegerField(default=3)
    guest_remaining = models.PositiveSmallIntegerField(default=3)
    winner_side = models.CharField(max_length=16, blank=True, default="")
    scheduled_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "team_battle_matches"
        ordering = ["-created_at"]
        indexes = [
            models.Index(
                fields=["battle_type", "status", "-created_at"], name="team_battle_status_idx"
            ),
        ]


class TeamBattleParticipant(models.Model):
    class Side(models.TextChoices):
        HOST = "host", "호스트"
        GUEST = "guest", "게스트"

    match = models.ForeignKey(
        TeamBattleMatch,
        on_delete=models.CASCADE,
        related_name="participants",
    )
    side = models.CharField(max_length=16, choices=Side.choices)
    order = models.PositiveSmallIntegerField()
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="team_battle_participations",
    )
    source_party = models.ForeignKey(
        Party,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    source_guild = models.ForeignKey(
        "community.Guild",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="+",
    )
    wins = models.PositiveSmallIntegerField(default=0)
    is_eliminated = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "team_battle_participants"
        ordering = ["side", "order"]
        constraints = [
            models.UniqueConstraint(
                fields=["match", "side", "order"], name="uniq_team_battle_lineup_order"
            ),
            models.UniqueConstraint(fields=["match", "user"], name="uniq_team_battle_user"),
        ]
        indexes = [
            models.Index(
                fields=["match", "side", "is_eliminated"], name="team_battle_side_alive_idx"
            ),
        ]


class TeamBattleRound(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "대기"
        LIVE = "live", "진행중"
        FINISHED = "finished", "종료"

    class Result(models.TextChoices):
        HOST = "host", "호스트 승"
        GUEST = "guest", "게스트 승"
        DRAW = "draw", "무승부"

    match = models.ForeignKey(
        TeamBattleMatch,
        on_delete=models.CASCADE,
        related_name="rounds",
    )
    round_number = models.PositiveSmallIntegerField()
    host_participant = models.ForeignKey(
        TeamBattleParticipant,
        on_delete=models.CASCADE,
        related_name="host_rounds",
    )
    guest_participant = models.ForeignKey(
        TeamBattleParticipant,
        on_delete=models.CASCADE,
        related_name="guest_rounds",
    )
    game = models.ForeignKey(
        "chess.Game",
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="team_battle_rounds",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    result = models.CharField(max_length=16, choices=Result.choices, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "team_battle_rounds"
        ordering = ["round_number"]
        constraints = [
            models.UniqueConstraint(
                fields=["match", "round_number"], name="uniq_team_battle_round"
            ),
        ]
        indexes = [
            models.Index(
                fields=["match", "status", "round_number"], name="team_battle_round_status_idx"
            ),
        ]
