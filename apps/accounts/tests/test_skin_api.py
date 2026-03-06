from rest_framework import status

from apps.accounts.models import Skin, SkinPointLog, UserSkin
from apps.accounts.tests.test_auth import BaseAPITestCase


class SkinApiTestCase(BaseAPITestCase):
    def setUp(self):
        super().setUp()
        self.user = self.create_verified_user(email="skin@test.com", nickname="스킨유저")
        self.client.force_authenticate(user=self.user)

        self.board_default, _ = Skin.objects.get_or_create(
            skin_type=Skin.SkinType.BOARD,
            css_class="skin-board-test-default",
            defaults={
                "name": "테스트 보드 기본",
                "price": 0,
                "description": "기본 보드",
                "is_default": True,
                "is_active": True,
                "sort_order": 0,
            },
        )
        self.piece_default, _ = Skin.objects.get_or_create(
            skin_type=Skin.SkinType.PIECES,
            css_class="skin-piece-test-default",
            defaults={
                "name": "테스트 기물 기본",
                "price": 0,
                "description": "기본 기물",
                "is_default": True,
                "is_active": True,
                "sort_order": 0,
            },
        )
        self.paid_piece, _ = Skin.objects.get_or_create(
            skin_type=Skin.SkinType.PIECES,
            css_class="skin-piece-test-paid",
            defaults={
                "name": "테스트 기물 유료",
                "price": 150,
                "description": "유료 기물",
                "is_default": False,
                "is_active": True,
                "sort_order": 10,
            },
        )

    def test_skin_catalog_success(self):
        response = self.client.get("/api/accounts/skins/me/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn("points", response.data)
        self.assertIn("board", response.data)
        self.assertIn("pieces", response.data)
        self.assertTrue(
            any(
                item["css_class"] == self.board_default.css_class for item in response.data["board"]
            )
        )
        self.assertTrue(
            any(
                item["css_class"] == self.piece_default.css_class
                for item in response.data["pieces"]
            )
        )

    def test_purchase_skin_deducts_points_and_creates_log(self):
        stats = self.user.stats
        stats.style_points = 200
        stats.save(update_fields=["style_points"])

        response = self.client.post(
            f"/api/accounts/skins/{self.paid_piece.id}/purchase/",
            {},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(
            UserSkin.objects.filter(user_id=self.user.id, skin_id=self.paid_piece.id).exists()
        )
        stats.refresh_from_db()
        self.assertEqual(stats.style_points, 50)

        log = SkinPointLog.objects.filter(
            user_id=self.user.id,
            reason=SkinPointLog.Reason.SKIN_PURCHASE,
            reference_id=str(self.paid_piece.id),
        ).latest("id")
        self.assertEqual(log.amount, -150)
        self.assertEqual(log.balance, 50)

    def test_select_skin_requires_ownership_for_paid_skin(self):
        response = self.client.post(
            f"/api/accounts/skins/{self.paid_piece.id}/select/",
            {},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        UserSkin.objects.create(user_id=self.user.id, skin_id=self.paid_piece.id)
        response = self.client.post(
            f"/api/accounts/skins/{self.paid_piece.id}/select/",
            {},
            format="json",
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.user.stats.refresh_from_db()
        self.assertEqual(self.user.stats.selected_piece_skin_id, self.paid_piece.id)
