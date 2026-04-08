from django.conf import settings
from django.db import models
from django.utils.text import slugify


class Tournament(models.Model):
    class Status(models.TextChoices):
        DRAFT = "draft", "준비중"
        OPEN = "open", "모집중"
        LIVE = "live", "진행중"
        FINISHED = "finished", "종료"

    title = models.CharField(max_length=80)
    slug = models.SlugField(max_length=96, unique=True, blank=True)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.DRAFT)
    max_participants = models.PositiveSmallIntegerField(default=8)
    minimum_rating = models.PositiveIntegerField(default=0)
    maximum_rating = models.PositiveIntegerField(default=4000)
    winner_title = models.CharField(max_length=80, blank=True, default="")
    start_at = models.DateTimeField()
    end_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="created_tournaments",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tournaments"
        ordering = ["start_at", "-created_at"]
        indexes = [
            models.Index(fields=["status", "start_at"], name="tournament_status_start_idx"),
        ]

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = slugify(self.title, allow_unicode=True)
        super().save(*args, **kwargs)


class TournamentEntry(models.Model):
    class Status(models.TextChoices):
        REGISTERED = "registered", "등록"
        CONFIRMED = "confirmed", "확정"
        ELIMINATED = "eliminated", "탈락"

    tournament = models.ForeignKey(Tournament, on_delete=models.CASCADE, related_name="entries")
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="tournament_entries",
    )
    seed = models.PositiveSmallIntegerField(null=True, blank=True)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.REGISTERED)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "tournament_entries"
        constraints = [
            models.UniqueConstraint(fields=["tournament", "user"], name="uniq_tournament_entry"),
        ]
        indexes = [
            models.Index(
                fields=["tournament", "status", "seed"], name="tournament_entry_status_seed_idx"
            ),
        ]
