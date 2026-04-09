import logging
import uuid

from django.db import transaction
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.exceptions import PermissionDenied, ValidationError

from apps.community.models import (
    Guild,
    GuildAuditLog,
    GuildChatMessage,
    GuildJoinRequest,
    GuildMember,
)
from apps.core.gcp.constants import FileType, GCPConstants
from apps.core.gcp.uploader import gcp_uploader
from apps.core.gcp.validators import GCPImageValidator

logger = logging.getLogger(__name__)


def _validate_guild_avatar_file(file):
    file_name = file.name
    GCPImageValidator.validate_file_name(file_name)
    ext = file_name.rsplit(".", 1)[-1].lower()
    GCPImageValidator.validate_extension(file_name, ext)
    GCPImageValidator.validate_mime_type(ext, file.content_type)
    GCPImageValidator.validate_file_size(file.size)
    return GCPImageValidator.normalize_image(file)


def _extract_old_avatar_key(guild: Guild) -> str | None:
    if not guild.avatar_url:
        return None
    return gcp_uploader.extract_key_from_url(guild.avatar_url)


def _upload_new_avatar(normalized_image) -> str:
    prefix = GCPConstants.PATH_MAPPING[FileType.GUILD_AVATAR]
    key = f"{prefix}/{uuid.uuid4()}.{normalized_image.extension}"
    gcp_uploader.upload_fileobj(
        normalized_image.content,
        key,
        content_type=normalized_image.content_type,
    )
    return f"{gcp_uploader.get_base_url()}{key}"


class GuildService:
    @staticmethod
    def list_guilds():
        return (
            Guild.objects.filter(is_active=True)
            .select_related("owner", "owner__stats")
            .annotate(
                pending_requests=Count(
                    "join_requests",
                    filter=Q(join_requests__status=GuildJoinRequest.Status.PENDING),
                )
            )
            .order_by("-updated_at", "-created_at", "-id")
        )

    @staticmethod
    def get_guild(guild_id: int) -> Guild:
        return get_object_or_404(
            Guild.objects.select_related("owner", "owner__stats").prefetch_related(
                "members__user__stats"
            ),
            pk=guild_id,
            is_active=True,
        )

    @staticmethod
    @transaction.atomic
    def create_guild(
        user,
        *,
        name: str,
        avatar=None,
        description: str,
        join_policy: str,
        min_rating: int,
        active_hours: str,
        contact_channel: str,
    ) -> Guild:
        if GuildMember.objects.filter(user=user).exists():
            raise ValidationError({"detail": ["이미 길드에 가입해 있습니다."]})
        avatar_url = None
        if avatar:
            avatar_url = _upload_new_avatar(_validate_guild_avatar_file(avatar))

        guild = Guild.objects.create(
            owner=user,
            name=name,
            avatar_url=avatar_url,
            description=description,
            join_policy=join_policy,
            min_rating=min_rating,
            active_hours=active_hours,
            contact_channel=contact_channel,
        )
        GuildMember.objects.create(guild=guild, user=user, role=GuildMember.Role.LEADER)
        GuildService._log(guild, actor=user, target_user=user, action="create", detail="길드 생성")
        return guild

    @staticmethod
    @transaction.atomic
    def request_join(user, guild_id: int, *, message: str) -> GuildJoinRequest:
        guild = Guild.objects.select_for_update().get(pk=guild_id, is_active=True)
        if GuildMember.objects.filter(user=user).exists():
            raise ValidationError({"detail": ["이미 다른 길드에 가입해 있습니다."]})
        if user.stats.rating < guild.min_rating:
            raise ValidationError({"detail": ["길드 가입 최소 레이팅을 충족하지 못했습니다."]})
        if guild.join_policy == Guild.JoinPolicy.OPEN:
            GuildMember.objects.create(guild=guild, user=user, role=GuildMember.Role.MEMBER)
            guild.member_count = GuildMember.objects.filter(guild=guild).count()
            guild.save(update_fields=["member_count", "updated_at"])
            GuildService._log(
                guild,
                actor=user,
                target_user=user,
                action="join_open",
                detail="자유 가입 승인",
            )
            return GuildJoinRequest.objects.create(
                guild=guild,
                user=user,
                status=GuildJoinRequest.Status.APPROVED,
                message=message,
                reviewed_at=timezone.now(),
            )
        return GuildJoinRequest.objects.create(guild=guild, user=user, message=message)

    @staticmethod
    def list_join_requests(actor, guild_id: int):
        GuildService._require_manager(actor.id, guild_id)
        return (
            GuildJoinRequest.objects.filter(
                guild_id=guild_id,
                status=GuildJoinRequest.Status.PENDING,
            )
            .select_related("user", "user__stats")
            .order_by("-created_at")
        )

    @staticmethod
    @transaction.atomic
    def review_join_request(actor, request_id: int, *, approve: bool) -> GuildJoinRequest:
        join_request = (
            GuildJoinRequest.objects.select_for_update()
            .select_related("guild", "user")
            .get(pk=request_id, status=GuildJoinRequest.Status.PENDING)
        )
        GuildService._require_manager(actor.id, join_request.guild_id)
        join_request.reviewed_by = actor
        join_request.reviewed_at = timezone.now()
        if approve:
            if GuildMember.objects.filter(user=join_request.user).exists():
                raise ValidationError({"detail": ["이미 길드에 가입한 사용자입니다."]})
            GuildMember.objects.create(
                guild=join_request.guild,
                user=join_request.user,
                role=GuildMember.Role.MEMBER,
            )
            join_request.status = GuildJoinRequest.Status.APPROVED
            join_request.guild.member_count = GuildMember.objects.filter(
                guild=join_request.guild
            ).count()
            join_request.guild.save(update_fields=["member_count", "updated_at"])
            GuildService._log(
                join_request.guild,
                actor=actor,
                target_user=join_request.user,
                action="approve_join",
                detail="가입 신청 승인",
            )
        else:
            join_request.status = GuildJoinRequest.Status.REJECTED
            GuildService._log(
                join_request.guild,
                actor=actor,
                target_user=join_request.user,
                action="reject_join",
                detail="가입 신청 거절",
            )
        join_request.save(update_fields=["status", "reviewed_by", "reviewed_at"])
        return join_request

    @staticmethod
    @transaction.atomic
    def update_notice(actor, guild_id: int, *, notice: str) -> Guild:
        GuildService._require_manager(actor.id, guild_id)
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        guild.notice = notice
        guild.save(update_fields=["notice", "updated_at"])
        GuildService._log(guild, actor=actor, action="update_notice", detail=notice[:120])
        return guild

    @staticmethod
    @transaction.atomic
    def update_avatar(actor, guild_id: int, *, file) -> Guild:
        GuildService._require_manager(actor.id, guild_id)
        guild = Guild.objects.select_for_update().get(pk=guild_id, is_active=True)
        normalized_image = _validate_guild_avatar_file(file)
        old_avatar_key = _extract_old_avatar_key(guild)
        guild.avatar_url = _upload_new_avatar(normalized_image)
        guild.save(update_fields=["avatar_url", "updated_at"])
        if old_avatar_key:
            try:
                gcp_uploader.delete_file(old_avatar_key)
            except Exception as exc:  # pragma: no cover - external cleanup best effort
                logger.warning("길드 아바타 삭제 실패: %s error=%s", old_avatar_key, exc)
        GuildService._log(
            guild, actor=actor, action="update_avatar", detail="길드 프로필 사진 변경"
        )
        return guild

    @staticmethod
    @transaction.atomic
    def update_member_role(actor, guild_id: int, member_user_id: int, *, role: str) -> GuildMember:
        GuildService._require_leader(actor.id, guild_id)
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        member = GuildMember.objects.select_for_update().get(guild=guild, user_id=member_user_id)
        if member.role == GuildMember.Role.LEADER:
            raise ValidationError({"detail": ["길드장 역할은 이 화면에서 변경할 수 없습니다."]})
        previous_role = member.role
        member.role = role
        member.save(update_fields=["role"])
        GuildService._log(
            guild,
            actor=actor,
            target_user=member.user,
            action="update_role",
            detail=f"{previous_role}->{role}",
        )
        return member

    @staticmethod
    @transaction.atomic
    def transfer_leadership(actor, guild_id: int, member_user_id: int) -> Guild:
        GuildService._require_leader(actor.id, guild_id)
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        current_leader = GuildMember.objects.select_for_update().get(
            guild=guild,
            user_id=actor.id,
            role=GuildMember.Role.LEADER,
        )
        new_leader = GuildMember.objects.select_for_update().get(
            guild=guild,
            user_id=member_user_id,
        )
        current_leader.role = GuildMember.Role.VICE
        new_leader.role = GuildMember.Role.LEADER
        current_leader.save(update_fields=["role"])
        new_leader.save(update_fields=["role"])
        guild.owner_id = member_user_id
        guild.save(update_fields=["owner", "updated_at"])
        GuildService._log(
            guild,
            actor=actor,
            target_user=new_leader.user,
            action="transfer_leader",
            detail="길드장 위임",
        )
        return guild

    @staticmethod
    @transaction.atomic
    def remove_member(actor, guild_id: int, member_user_id: int) -> None:
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        GuildService._require_manager(actor.id, guild.id)
        member = GuildMember.objects.select_for_update().get(guild=guild, user_id=member_user_id)
        if member.role == GuildMember.Role.LEADER:
            raise ValidationError({"detail": ["길드장은 추방할 수 없습니다."]})
        target_user = member.user
        member.delete()
        guild.member_count = GuildMember.objects.filter(guild=guild).count()
        guild.save(update_fields=["member_count", "updated_at"])
        GuildService._log(
            guild,
            actor=actor,
            target_user=target_user,
            action="kick",
            detail="멤버 추방",
        )

    @staticmethod
    @transaction.atomic
    def leave_guild(user, guild_id: int) -> None:
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        member = GuildMember.objects.select_for_update().get(guild=guild, user=user)
        if member.role == GuildMember.Role.LEADER:
            raise ValidationError({"detail": ["길드장은 위임 후 탈퇴할 수 있습니다."]})
        member.delete()
        guild.member_count = GuildMember.objects.filter(guild=guild).count()
        guild.save(update_fields=["member_count", "updated_at"])
        GuildService._log(guild, actor=user, target_user=user, action="leave", detail="길드 탈퇴")

    @staticmethod
    def list_chat_messages(actor, guild_id: int):
        GuildService._require_member(actor.id, guild_id)
        return (
            GuildChatMessage.objects.filter(guild_id=guild_id)
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
    def post_chat_message(actor, guild_id: int, *, content: str) -> GuildChatMessage:
        GuildService._require_member(actor.id, guild_id)
        guild = Guild.objects.get(pk=guild_id, is_active=True)
        return GuildChatMessage.objects.create(guild=guild, user=actor, content=content.strip())

    @staticmethod
    def list_audit_logs(actor, guild_id: int):
        GuildService._require_manager(actor.id, guild_id)
        return (
            GuildAuditLog.objects.filter(guild_id=guild_id)
            .select_related("actor", "target_user")
            .order_by("-created_at")[:50]
        )

    @staticmethod
    def _require_member(user_id: int, guild_id: int) -> GuildMember:
        membership = GuildMember.objects.filter(guild_id=guild_id, user_id=user_id).first()
        if not membership:
            raise PermissionDenied("길드 멤버만 접근할 수 있습니다.")
        return membership

    @staticmethod
    def _require_manager(user_id: int, guild_id: int) -> GuildMember:
        membership = GuildService._require_member(user_id, guild_id)
        if membership.role not in {
            GuildMember.Role.LEADER,
            GuildMember.Role.VICE,
            GuildMember.Role.MANAGER,
        }:
            raise PermissionDenied("길드 관리 권한이 필요합니다.")
        return membership

    @staticmethod
    def _require_leader(user_id: int, guild_id: int) -> GuildMember:
        membership = GuildService._require_member(user_id, guild_id)
        if membership.role != GuildMember.Role.LEADER:
            raise PermissionDenied("길드장 권한이 필요합니다.")
        return membership

    @staticmethod
    def _log(guild, *, actor=None, target_user=None, action: str, detail: str = "") -> None:
        GuildAuditLog.objects.create(
            guild=guild,
            actor=actor,
            target_user=target_user,
            action=action,
            detail=detail,
        )
