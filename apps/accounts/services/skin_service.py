from collections import defaultdict

from django.db import IntegrityError, transaction
from django.db.models import F
from django.utils import timezone

from rest_framework import status
from rest_framework.exceptions import ValidationError

from apps.accounts.models import Skin, SkinPointLog, UserSkin
from apps.accounts.models.user_stats import UserStats
from apps.accounts.services.base_service import ServiceResult, _ok

DEFAULT_BOARD_CLASS = "skin-board-classic"
DEFAULT_PIECE_CLASS = "skin-piece-classic"


class SkinService:
    @staticmethod
    def _default_skin(skin_type: str) -> Skin:
        skin = Skin.objects.filter(skin_type=skin_type, is_default=True, is_active=True).first()
        if skin:
            return skin
        fallback = (
            Skin.objects.filter(skin_type=skin_type, is_active=True)
            .order_by("sort_order", "id")
            .first()
        )
        if fallback:
            return fallback
        label = "보드" if skin_type == Skin.SkinType.BOARD else "기물"
        raise ValidationError(
            {"message": f"{label} 기본 스킨이 설정되지 않았습니다. 운영자에게 문의해주세요."}
        )

    @staticmethod
    def _ensure_selected(stats: UserStats) -> None:
        updates: list[str] = []
        if not stats.selected_board_skin_id:
            stats.selected_board_skin = SkinService._default_skin(Skin.SkinType.BOARD)
            updates.append("selected_board_skin")
        if not stats.selected_piece_skin_id:
            stats.selected_piece_skin = SkinService._default_skin(Skin.SkinType.PIECES)
            updates.append("selected_piece_skin")
        if updates:
            stats.save(update_fields=updates)

    @staticmethod
    def _owned_skin_ids(user_id: int) -> set[int]:
        return set(UserSkin.objects.filter(user_id=user_id).values_list("skin_id", flat=True))

    @staticmethod
    def get_skin_catalog(user) -> ServiceResult:
        stats, _ = UserStats.objects.get_or_create(user=user)
        SkinService._ensure_selected(stats)
        owned_ids = SkinService._owned_skin_ids(user.id)
        skins = list(
            Skin.objects.filter(is_active=True).order_by("skin_type", "sort_order", "price", "id")
        )
        grouped: dict[str, list[dict]] = defaultdict(list)

        for skin in skins:
            selected = (
                skin.id == stats.selected_board_skin_id
                if skin.skin_type == Skin.SkinType.BOARD
                else skin.id == stats.selected_piece_skin_id
            )
            grouped[skin.skin_type].append(
                {
                    "id": skin.id,
                    "name": skin.name,
                    "skin_type": skin.skin_type,
                    "price": skin.price,
                    "css_class": skin.css_class,
                    "preview_image": skin.preview_image,
                    "description": skin.description,
                    "is_default": skin.is_default,
                    "is_active": skin.is_active,
                    "sort_order": skin.sort_order,
                    "owned": skin.is_default or (skin.id in owned_ids),
                    "selected": selected,
                }
            )

        return _ok(
            {
                "points": stats.style_points,
                "board": grouped.get(Skin.SkinType.BOARD, []),
                "pieces": grouped.get(Skin.SkinType.PIECES, []),
            },
            status.HTTP_200_OK,
        )

    @staticmethod
    @transaction.atomic
    def purchase_skin(user, skin_id: int) -> ServiceResult:
        stats = UserStats.objects.select_for_update().get(user=user)
        skin = Skin.objects.select_for_update().filter(id=skin_id, is_active=True).first()
        if not skin:
            raise ValidationError({"message": "구매할 수 있는 스킨을 찾지 못했습니다."})
        if skin.is_default or skin.price <= 0:
            raise ValidationError({"message": "기본 스킨은 구매가 필요하지 않습니다."})
        if UserSkin.objects.filter(user_id=user.id, skin_id=skin.id).exists():
            raise ValidationError({"message": "이미 보유한 스킨입니다."})
        if stats.style_points < skin.price:
            need = skin.price - stats.style_points
            raise ValidationError({"message": f"포인트가 부족합니다. {need}P 더 필요합니다."})

        stats.style_points = F("style_points") - skin.price
        stats.save(update_fields=["style_points"])
        stats.refresh_from_db(fields=["style_points"])

        try:
            UserSkin.objects.create(
                user_id=user.id,
                skin_id=skin.id,
                acquired_method=UserSkin.AcquireMethod.PURCHASE,
            )
        except IntegrityError as err:
            raise ValidationError({"message": "이미 보유한 스킨입니다."}) from err

        SkinPointLog.objects.create(
            user_id=user.id,
            amount=-skin.price,
            balance=stats.style_points,
            reason=SkinPointLog.Reason.SKIN_PURCHASE,
            reference_id=str(skin.id),
            created_at=timezone.now(),
        )

        return _ok(
            {
                "message": f"{skin.name} 스킨을 구매했습니다.",
                "skin_id": skin.id,
                "new_balance": stats.style_points,
            },
            status.HTTP_200_OK,
        )

    @staticmethod
    @transaction.atomic
    def select_skin(user, skin_id: int) -> ServiceResult:
        stats = (
            UserStats.objects.select_for_update()
            .select_related("selected_board_skin", "selected_piece_skin")
            .get(user=user)
        )
        skin = Skin.objects.filter(id=skin_id, is_active=True).first()
        if not skin:
            raise ValidationError({"message": "장착할 스킨을 찾지 못했습니다."})

        if not skin.is_default:
            owns = UserSkin.objects.filter(user_id=user.id, skin_id=skin.id).exists()
            if not owns:
                raise ValidationError({"message": "보유하지 않은 스킨입니다. 먼저 구매해주세요."})

        if skin.skin_type == Skin.SkinType.BOARD:
            stats.selected_board_skin = skin
            stats.save(update_fields=["selected_board_skin"])
            key = "selected_board_skin"
        else:
            stats.selected_piece_skin = skin
            stats.save(update_fields=["selected_piece_skin"])
            key = "selected_piece_skin"

        return _ok(
            {
                "message": f"{skin.name} 스킨이 적용되었습니다.",
                key: {
                    "id": skin.id,
                    "name": skin.name,
                    "css_class": skin.css_class,
                    "skin_type": skin.skin_type,
                },
            },
            status.HTTP_200_OK,
        )

    @staticmethod
    def point_history(user, limit: int = 30) -> ServiceResult:
        size = min(max(int(limit or 30), 1), 100)
        logs = SkinPointLog.objects.filter(user_id=user.id).order_by("-created_at", "-id")[:size]
        items = [
            {
                "id": log.id,
                "amount": log.amount,
                "balance": log.balance,
                "reason": log.reason,
                "reason_label": log.get_reason_display(),
                "reference_id": log.reference_id,
                "created_at": log.created_at,
            }
            for log in logs
        ]
        return _ok({"results": items}, status.HTTP_200_OK)

    @staticmethod
    @transaction.atomic
    def award_points(user_id: int, amount: int, reason: str, reference_id: str = "") -> None:
        if amount <= 0:
            return
        stats = UserStats.objects.select_for_update().get(user_id=user_id)
        stats.style_points = F("style_points") + amount
        stats.save(update_fields=["style_points"])
        stats.refresh_from_db(fields=["style_points"])
        SkinPointLog.objects.create(
            user_id=user_id,
            amount=amount,
            balance=stats.style_points,
            reason=reason,
            reference_id=reference_id,
            created_at=timezone.now(),
        )
