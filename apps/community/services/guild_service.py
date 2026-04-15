import logging
import uuid

from django.db import transaction
from django.db.models import Count, Prefetch, Q
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.exceptions import PermissionDenied, ValidationError

from apps.community.models import (
    Guild,
    GuildChatMessage,
    GuildJoinRequest,
    GuildMember,
    GuildNotice,
)
from apps.core.gcp.constants import FileType, GCPConstants
from apps.core.gcp.uploader import gcp_uploader
from apps.core.gcp.validators import GCPImageValidator
from apps.notifications.services import NotificationService

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
    GUILD_LIST_ONLY_FIELDS = (
        "id",
        "name",
        "slug",
        "avatar_url",
        "description",
        "notice",
        "join_policy",
        "min_rating",
        "active_hours",
        "contact_channel",
        "team_rating",
        "member_count",
        "created_at",
        "updated_at",
        "owner_id",
        "owner__id",
        "owner__nickname",
        "owner__avatar_url",
        "owner__stats__rating",
        "owner__stats__featured_achievement_key",
    )

    GUILD_MEMBER_ONLY_FIELDS = (
        "id",
        "guild_id",
        "user_id",
        "role",
        "joined_at",
        "user__id",
        "user__nickname",
        "user__avatar_url",
        "user__stats__rating",
        "user__stats__featured_achievement_key",
    )

    @staticmethod
    def _member_prefetch():
        return Prefetch(
            "members",
            queryset=GuildMember.objects.select_related("user", "user__stats").only(
                *GuildService.GUILD_MEMBER_ONLY_FIELDS
            ),
        )

    @staticmethod
    def list_guilds():
        return (
            Guild.objects.filter(is_active=True)
            .select_related("owner", "owner__stats")
            .only(*GuildService.GUILD_LIST_ONLY_FIELDS)
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
            Guild.objects.select_related("owner", "owner__stats")
            .only(*GuildService.GUILD_LIST_ONLY_FIELDS)
            .prefetch_related(GuildService._member_prefetch()),
            pk=guild_id,
            is_active=True,
        )

    @staticmethod
    def get_current_guild(user) -> Guild | None:
        membership = (
            GuildMember.objects.filter(user=user, guild__is_active=True)
            .select_related("guild", "guild__owner", "guild__owner__stats")
            .order_by("-joined_at")
            .first()
        )
        if not membership:
            return None
        return GuildService.get_guild(membership.guild_id)

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
            .only(
                "id",
                "guild_id",
                "user_id",
                "status",
                "message",
                "created_at",
                "reviewed_at",
                "user__id",
                "user__nickname",
                "user__avatar_url",
                "user__stats__rating",
                "user__stats__featured_achievement_key",
            )
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
        else:
            join_request.status = GuildJoinRequest.Status.REJECTED
        join_request.save(update_fields=["status", "reviewed_by", "reviewed_at"])
        return join_request

    @staticmethod
    @transaction.atomic
    def update_notice(actor, guild_id: int, *, notice: str) -> Guild:
        GuildService._require_manager(actor.id, guild_id)
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        notice_text = notice.strip()
        guild.notice = notice_text
        guild.save(update_fields=["notice", "updated_at"])
        notice_entry = None
        if notice_text:
            notice_entry = GuildNotice.objects.create(
                guild=guild,
                author=actor,
                content=notice_text,
            )
            recipients = list(
                GuildMember.objects.filter(guild=guild)
                .exclude(user_id=actor.id)
                .select_related("user")
                .only("user_id", "user__id")
            )
            if recipients:
                rows = [
                    {
                        "user": membership.user,
                        "type": "admin_notice",
                        "title": f"{guild.name} 공지",
                        "message": f"{actor.nickname}: {notice_text[:100]}",
                        "payload": {
                            "guild_id": guild.id,
                            "notice_id": notice_entry.id,
                            "url": "/guilds/manage/",
                        },
                    }
                    for membership in recipients
                ]
                transaction.on_commit(
                    lambda rows=rows: NotificationService.bulk_create_notifications(
                        rows,
                        push=True,
                    )
                )
        return guild

    @staticmethod
    def list_notices(actor, guild_id: int):
        GuildService._require_member(actor.id, guild_id)
        return (
            GuildNotice.objects.filter(guild_id=guild_id)
            .select_related("author", "author__stats")
            .only(
                "id",
                "guild_id",
                "content",
                "created_at",
                "author__id",
                "author__nickname",
                "author__avatar_url",
                "author__stats__rating",
                "author__stats__featured_achievement_key",
            )[:30]
        )

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
        return guild

    @staticmethod
    @transaction.atomic
    def update_member_role(actor, guild_id: int, member_user_id: int, *, role: str) -> GuildMember:
        GuildService._require_leader(actor.id, guild_id)
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        member = GuildMember.objects.select_for_update().get(guild=guild, user_id=member_user_id)
        if member.role == GuildMember.Role.LEADER:
            raise ValidationError({"detail": ["길드장 역할은 이 화면에서 변경할 수 없습니다."]})
        member.role = role
        member.save(update_fields=["role"])
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
        return guild

    @staticmethod
    @transaction.atomic
    def remove_member(actor, guild_id: int, member_user_id: int) -> None:
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        GuildService._require_manager(actor.id, guild.id)
        member = GuildMember.objects.select_for_update().get(guild=guild, user_id=member_user_id)
        if member.role == GuildMember.Role.LEADER:
            raise ValidationError({"detail": ["길드장은 추방할 수 없습니다."]})
        member.delete()
        guild.member_count = GuildMember.objects.filter(guild=guild).count()
        guild.save(update_fields=["member_count", "updated_at"])

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
