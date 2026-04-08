from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.exceptions import PermissionDenied, ValidationError

from apps.accounts.models import User
from apps.community.models import Party, PartyChatMessage, PartyInvite, PartyMember
from apps.core.access import AccessGuard


class PartyService:
    @staticmethod
    def list_parties():
        return Party.objects.select_related("leader", "leader__stats").prefetch_related(
            "members__user__stats"
        )

    @staticmethod
    def get_party(party_id: int) -> Party:
        return get_object_or_404(
            Party.objects.select_related("leader", "leader__stats").prefetch_related(
                "members__user__stats"
            ),
            pk=party_id,
        )

    @staticmethod
    def list_pending_invites(user):
        return (
            PartyInvite.objects.filter(
                to_user=user,
                status=PartyInvite.Status.PENDING,
            )
            .select_related(
                "party",
                "party__leader",
                "party__leader__stats",
                "from_user",
                "from_user__stats",
                "to_user",
                "to_user__stats",
            )
            .order_by("-created_at")
        )

    @staticmethod
    @transaction.atomic
    def create_party(user, *, title: str, description: str) -> Party:
        if PartyMember.objects.filter(
            user=user,
            party__status__in=[
                Party.Status.OPEN,
                Party.Status.READY,
                Party.Status.QUEUED,
                Party.Status.BATTLING,
            ],
        ).exists():
            raise ValidationError({"detail": ["이미 활성 파티에 속해 있습니다."]})
        party = Party.objects.create(leader=user, title=title, description=description)
        PartyMember.objects.create(party=party, user=user, slot=1, is_ready=True)
        return party

    @staticmethod
    @transaction.atomic
    def invite_member(actor, party_id: int, *, to_user_id: int) -> PartyInvite:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyService._require_leader(actor.id, party)
        AccessGuard.require_other_user(
            actor.id,
            to_user_id,
            field_name="user_id",
            message="자기 자신은 초대할 수 없습니다.",
        )
        if PartyMember.objects.filter(party=party).count() >= party.max_members:
            raise ValidationError({"detail": ["파티 정원이 가득 찼습니다."]})
        target = get_object_or_404(User, pk=to_user_id)
        if PartyMember.objects.filter(
            user=target,
            party__status__in=[
                Party.Status.OPEN,
                Party.Status.READY,
                Party.Status.QUEUED,
                Party.Status.BATTLING,
            ],
        ).exists():
            raise ValidationError({"detail": ["상대가 이미 다른 활성 파티에 속해 있습니다."]})
        return PartyInvite.objects.create(party=party, from_user=actor, to_user=target)

    @staticmethod
    @transaction.atomic
    def respond_invite(user, invite_id: int, *, accept: bool) -> PartyInvite:
        invite = (
            PartyInvite.objects.select_for_update()
            .select_related("party")
            .get(pk=invite_id, to_user=user, status=PartyInvite.Status.PENDING)
        )
        if accept:
            if PartyMember.objects.filter(
                user=user,
                party__status__in=[
                    Party.Status.OPEN,
                    Party.Status.READY,
                    Party.Status.QUEUED,
                    Party.Status.BATTLING,
                ],
            ).exists():
                raise ValidationError({"detail": ["이미 다른 활성 파티에 속해 있습니다."]})
            if PartyMember.objects.filter(party=invite.party).count() >= invite.party.max_members:
                raise ValidationError({"detail": ["파티 정원이 가득 찼습니다."]})
            PartyMember.objects.create(party=invite.party, user=user)
            invite.status = PartyInvite.Status.ACCEPTED
        else:
            invite.status = PartyInvite.Status.DECLINED
        invite.responded_at = timezone.now()
        invite.save(update_fields=["status", "responded_at"])
        return invite

    @staticmethod
    @transaction.atomic
    def transfer_leader(actor, party_id: int, *, user_id: int) -> Party:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyService._require_leader(actor.id, party)
        PartyMember.objects.get(party=party, user_id=user_id)
        party.leader_id = user_id
        party.save(update_fields=["leader", "updated_at"])
        return party

    @staticmethod
    @transaction.atomic
    def remove_member(actor, party_id: int, *, user_id: int) -> None:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyService._require_leader(actor.id, party)
        if user_id == party.leader_id:
            raise ValidationError({"detail": ["파티장은 추방할 수 없습니다."]})
        PartyMember.objects.filter(party=party, user_id=user_id).delete()
        PartyInvite.objects.filter(
            party=party,
            to_user_id=user_id,
            status=PartyInvite.Status.PENDING,
        ).update(
            status=PartyInvite.Status.EXPIRED,
            responded_at=timezone.now(),
        )

    @staticmethod
    @transaction.atomic
    def leave_party(user, party_id: int) -> Party | None:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyMember.objects.get(party=party, user=user)
        PartyMember.objects.filter(party=party, user=user).delete()
        remaining = list(PartyMember.objects.filter(party=party).order_by("joined_at"))
        if not remaining:
            party.status = Party.Status.CLOSED
            party.save(update_fields=["status", "updated_at"])
            return None
        if party.leader_id == user.id:
            party.leader_id = remaining[0].user_id
            party.save(update_fields=["leader", "updated_at"])
        return party

    @staticmethod
    @transaction.atomic
    def set_ready(user, party_id: int, *, ready: bool) -> PartyMember:
        membership = (
            PartyMember.objects.select_for_update()
            .select_related("party")
            .get(party_id=party_id, user=user)
        )
        membership.is_ready = ready
        membership.save(update_fields=["is_ready"])
        return membership

    @staticmethod
    @transaction.atomic
    def assign_slot(actor, party_id: int, *, user_id: int, slot: int) -> PartyMember:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyService._require_leader(actor.id, party)
        if party.lineup_locked:
            raise ValidationError({"detail": ["라인업이 이미 고정되었습니다."]})
        PartyMember.objects.filter(party=party, slot=slot).exclude(user_id=user_id).update(
            slot=None
        )
        member = PartyMember.objects.select_for_update().get(party=party, user_id=user_id)
        member.slot = slot
        member.save(update_fields=["slot"])
        return member

    @staticmethod
    @transaction.atomic
    def lock_lineup(actor, party_id: int) -> Party:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyService._require_leader(actor.id, party)
        member_count = PartyMember.objects.filter(party=party).count()
        if member_count != party.max_members:
            raise ValidationError({"detail": ["3명이 모두 모여야 라인업을 고정할 수 있습니다."]})
        assigned_slots = PartyMember.objects.filter(party=party, slot__isnull=False).count()
        if assigned_slots != party.max_members:
            raise ValidationError({"detail": ["1,2,3번 라인업을 모두 지정해주세요."]})
        party.lineup_locked = True
        party.status = Party.Status.READY
        party.save(update_fields=["lineup_locked", "status", "updated_at"])
        return party

    @staticmethod
    @transaction.atomic
    def unlock_lineup(actor, party_id: int) -> Party:
        party = Party.objects.select_for_update().get(pk=party_id)
        PartyService._require_leader(actor.id, party)
        if party.status in {Party.Status.QUEUED, Party.Status.BATTLING}:
            raise ValidationError(
                {"detail": ["매칭 대기/대전 중에는 라인업을 해제할 수 없습니다."]}
            )
        party.lineup_locked = False
        party.status = Party.Status.OPEN
        party.save(update_fields=["lineup_locked", "status", "updated_at"])
        return party

    @staticmethod
    def list_chat_messages(actor, party_id: int):
        PartyService._require_member(actor.id, party_id)
        return (
            PartyChatMessage.objects.filter(party_id=party_id)
            .select_related("user", "user__stats")
            .only(
                "id",
                "content",
                "created_at",
                "user__id",
                "user__nickname",
                "user__avatar_url",
                "user__stats__featured_achievement_key",
            )[:50]
        )

    @staticmethod
    @transaction.atomic
    def post_chat_message(actor, party_id: int, *, content: str) -> PartyChatMessage:
        PartyService._require_member(actor.id, party_id)
        party = Party.objects.get(pk=party_id)
        return PartyChatMessage.objects.create(party=party, user=actor, content=content.strip())

    @staticmethod
    def _require_member(user_id: int, party_id: int) -> PartyMember:
        membership = PartyMember.objects.filter(party_id=party_id, user_id=user_id).first()
        if not membership:
            raise PermissionDenied("파티 멤버만 접근할 수 있습니다.")
        return membership

    @staticmethod
    def _require_leader(user_id: int, party: Party) -> None:
        if party.leader_id != user_id:
            raise PermissionDenied("파티장 권한이 필요합니다.")
