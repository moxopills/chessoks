from django.db import transaction
from django.db.models import F, Prefetch
from django.shortcuts import get_object_or_404
from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.community.models import (
    BoardCategory,
    BoardComment,
    BoardCommentLike,
    BoardPost,
    BoardReport,
)


class BoardService:
    BOARD_SUMMARY_ONLY_FIELDS = (
        "id",
        "title",
        "content",
        "is_pinned",
        "is_blinded",
        "view_count",
        "comment_count",
        "guild_name",
        "created_at",
        "author_id",
        "category_id",
        "author__id",
        "author__nickname",
        "author__avatar_url",
        "author__stats__rating",
        "author__stats__featured_achievement_key",
        "category__id",
        "category__code",
        "category__title",
        "category__description",
        "category__sort_order",
        "category__is_recruitment",
    )

    BOARD_DETAIL_ONLY_FIELDS = BOARD_SUMMARY_ONLY_FIELDS + (
        "updated_at",
        "recruitment_slots",
        "minimum_rating",
        "active_time_band",
        "join_policy_text",
        "contact_method",
    )

    BOARD_COMMENT_ONLY_FIELDS = (
        "id",
        "post_id",
        "author_id",
        "content",
        "is_blinded",
        "created_at",
        "like_count",
        "author__id",
        "author__nickname",
        "author__avatar_url",
        "author__stats__rating",
        "author__stats__featured_achievement_key",
        "post__author_id",
    )

    @staticmethod
    def ensure_default_categories() -> None:
        categories = [
            ("recruit", "모집", "길드/파티 모집 게시판", 1, True),
            ("free", "자유", "자유 게시판", 2, False),
            ("puzzle-guide", "퍼즐공략", "퍼즐 풀이와 해설 공유", 3, False),
            ("knowledge", "지식", "체스 지식과 일반 공략 공유", 4, False),
        ]
        legacy_remaps = {
            "guild-recruit": categories[0],
            "guide": categories[3],
        }
        desired_codes = {code for code, *_ in categories}

        with transaction.atomic():
            for legacy_code, (
                target_code,
                title,
                description,
                sort_order,
                is_recruitment,
            ) in legacy_remaps.items():
                legacy = BoardCategory.objects.filter(code=legacy_code).first()
                target_exists = BoardCategory.objects.filter(code=target_code).exists()
                if legacy and not target_exists:
                    legacy.code = target_code
                    legacy.title = title
                    legacy.description = description
                    legacy.sort_order = sort_order
                    legacy.is_recruitment = is_recruitment
                    legacy.is_enabled = True
                    legacy.save(
                        update_fields=[
                            "code",
                            "title",
                            "description",
                            "sort_order",
                            "is_recruitment",
                            "is_enabled",
                        ]
                    )

            for code, title, description, sort_order, is_recruitment in categories:
                BoardCategory.objects.update_or_create(
                    code=code,
                    defaults={
                        "title": title,
                        "description": description,
                        "sort_order": sort_order,
                        "is_recruitment": is_recruitment,
                        "is_enabled": True,
                    },
                )

            BoardCategory.objects.exclude(code__in=desired_codes).update(is_enabled=False)

    @staticmethod
    def list_categories():
        BoardService.ensure_default_categories()
        return BoardCategory.objects.filter(is_enabled=True).order_by("sort_order", "id")

    @staticmethod
    def list_posts(*, category_code: str | None, limit: int | None = None, author=None):
        queryset = (
            BoardPost.objects.select_related("author", "author__stats", "category")
            .only(*BoardService.BOARD_SUMMARY_ONLY_FIELDS)
            .filter(category__is_enabled=True, is_blinded=False)
        )
        if category_code:
            queryset = queryset.filter(category__code=category_code)
        if author is not None:
            queryset = queryset.filter(author=author)
        if limit:
            return queryset[:limit]
        return queryset

    @staticmethod
    @transaction.atomic
    def create_post(
        author, *, category_code: str, title: str, content: str, extra: dict
    ) -> BoardPost:
        category = get_object_or_404(BoardCategory, code=category_code, is_enabled=True)
        return BoardPost.objects.create(
            category=category,
            author=author,
            title=title,
            content=content,
            guild_name=extra.get("guild_name", ""),
            recruitment_slots=extra.get("recruitment_slots"),
            minimum_rating=extra.get("minimum_rating"),
            active_time_band=extra.get("active_time_band", ""),
            join_policy_text=extra.get("join_policy_text", ""),
            contact_method=extra.get("contact_method", ""),
        )

    @staticmethod
    def get_post(post_id: int, *, increment_view: bool = False, viewer=None) -> BoardPost:
        if increment_view:
            BoardPost.objects.filter(pk=post_id).update(view_count=F("view_count") + 1)
        comments_queryset = BoardComment.objects.select_related(
            "author",
            "author__stats",
            "post",
        ).only(*BoardService.BOARD_COMMENT_ONLY_FIELDS)
        if viewer and getattr(viewer, "is_authenticated", False):
            comments_queryset = comments_queryset.prefetch_related(
                Prefetch(
                    "likes",
                    queryset=BoardCommentLike.objects.filter(user=viewer).only("id", "comment_id"),
                    to_attr="viewer_likes",
                )
            )
        return get_object_or_404(
            BoardPost.objects.select_related("author", "author__stats", "category")
            .only(*BoardService.BOARD_DETAIL_ONLY_FIELDS)
            .prefetch_related(Prefetch("comments", queryset=comments_queryset)),
            pk=post_id,
        )

    @staticmethod
    @transaction.atomic
    def create_comment(author, post_id: int, *, content: str) -> BoardComment:
        post = BoardPost.objects.select_for_update().get(pk=post_id)
        comment = BoardComment.objects.create(post=post, author=author, content=content)
        BoardPost.objects.filter(pk=post_id).update(
            comment_count=F("comment_count") + 1,
            last_commented_at=timezone.now(),
        )
        return comment

    @staticmethod
    @transaction.atomic
    def delete_comment(actor, *, comment_id: int) -> None:
        comment = (
            BoardComment.objects.select_for_update()
            .select_related("author", "post")
            .get(pk=comment_id)
        )
        if (
            comment.author_id != actor.id
            and comment.post.author_id != actor.id
            and not getattr(actor, "is_staff", False)
        ):
            raise ValidationError({"detail": ["삭제 권한이 없습니다."]})
        post_id = comment.post_id
        comment.delete()
        BoardPost.objects.filter(pk=post_id, comment_count__gt=0).update(
            comment_count=F("comment_count") - 1
        )

    @staticmethod
    @transaction.atomic
    def delete_post(actor, *, post_id: int) -> None:
        post = BoardPost.objects.select_for_update().select_related("author").get(pk=post_id)
        if post.author_id != actor.id and not getattr(actor, "is_staff", False):
            raise ValidationError({"detail": ["본인이 작성한 게시글만 삭제할 수 있습니다."]})
        post.delete()

    @staticmethod
    @transaction.atomic
    def toggle_comment_like(actor, *, comment_id: int) -> tuple[BoardComment, bool]:
        comment = BoardComment.objects.select_for_update().get(pk=comment_id)
        like = BoardCommentLike.objects.filter(comment=comment, user=actor).first()
        if like:
            like.delete()
            BoardComment.objects.filter(pk=comment_id).update(like_count=F("like_count") - 1)
            liked = False
        else:
            BoardCommentLike.objects.create(comment=comment, user=actor)
            BoardComment.objects.filter(pk=comment_id).update(like_count=F("like_count") + 1)
            liked = True
        comment.refresh_from_db(fields=["id", "like_count", "post_id"])
        return comment, liked

    @staticmethod
    @transaction.atomic
    def create_report(
        reporter, *, target_type: str, post_id: int | None, comment_id: int | None, reason: str
    ):
        if target_type == BoardReport.TargetType.POST and not post_id:
            raise ValidationError({"post_id": ["게시글 신고 대상이 필요합니다."]})
        if target_type == BoardReport.TargetType.COMMENT and not comment_id:
            raise ValidationError({"comment_id": ["댓글 신고 대상이 필요합니다."]})
        return BoardReport.objects.create(
            reporter=reporter,
            target_type=target_type,
            post_id=post_id,
            comment_id=comment_id,
            reason=reason,
        )
