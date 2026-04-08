from django.db import transaction
from django.db.models import BooleanField, Count, Exists, OuterRef, Value

from rest_framework.exceptions import ValidationError

from apps.community.models import Tournament, TournamentEntry
from apps.core.access import AccessGuard


class TournamentService:
    @staticmethod
    def list_tournaments(user=None):
        queryset = Tournament.objects.annotate(entry_count=Count("entries"))
        if user and getattr(user, "is_authenticated", False):
            queryset = queryset.annotate(
                is_registered=Exists(
                    TournamentEntry.objects.filter(
                        tournament_id=OuterRef("pk"),
                        user=user,
                    )
                )
            )
        else:
            queryset = queryset.annotate(is_registered=Value(False, output_field=BooleanField()))
        return queryset.order_by("start_at", "-created_at")

    @staticmethod
    @transaction.atomic
    def create_tournament(
        actor,
        *,
        title: str,
        description: str,
        max_participants: int,
        minimum_rating: int,
        maximum_rating: int,
        start_at,
    ) -> Tournament:
        AccessGuard.require_staff(actor)
        return Tournament.objects.create(
            title=title,
            description=description,
            status=Tournament.Status.OPEN,
            max_participants=max_participants,
            minimum_rating=minimum_rating,
            maximum_rating=maximum_rating,
            start_at=start_at,
            created_by=actor,
        )

    @staticmethod
    @transaction.atomic
    def register(user, tournament_id: int) -> TournamentEntry:
        tournament = Tournament.objects.select_for_update().get(pk=tournament_id)
        if tournament.status != Tournament.Status.OPEN:
            raise ValidationError({"detail": ["현재 참가 신청을 받을 수 없는 대회입니다."]})
        if not (tournament.minimum_rating <= user.stats.rating <= tournament.maximum_rating):
            raise ValidationError({"detail": ["참가 조건 레이팅을 충족하지 못했습니다."]})
        if (
            TournamentEntry.objects.filter(tournament=tournament).count()
            >= tournament.max_participants
        ):
            raise ValidationError({"detail": ["대회 정원이 가득 찼습니다."]})
        return TournamentEntry.objects.create(tournament=tournament, user=user)

    @staticmethod
    @transaction.atomic
    def unregister(user, tournament_id: int) -> None:
        TournamentEntry.objects.filter(tournament_id=tournament_id, user=user).delete()
