from django.test import TestCase

from rest_framework import status
from rest_framework.test import APIClient

from apps.accounts.tests.test_auth import User
from apps.chess.models import Game, Room
from apps.chess.services.game_service import GameService


class CoreFlowApiTestCase(TestCase):
    def setUp(self):
        self.host_client = APIClient()
        self.guest_client = APIClient()
        self.host = User.objects.create_user(
            email="flowhost@test.com", nickname="흐름호스트", password="Pass123!"
        )
        self.guest = User.objects.create_user(
            email="flowguest@test.com", nickname="흐름게스트", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.host, room_type="custom")

        assert self.host_client.login(email=self.host.email, password="Pass123!")
        assert self.guest_client.login(email=self.guest.email, password="Pass123!")

    def test_room_ready_start_and_move_flow(self):
        # guest joins
        response = self.guest_client.post(f"/api/chess/rooms/{self.room.id}/join/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # host ready
        response = self.host_client.post(
            f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # guest ready
        response = self.guest_client.post(
            f"/api/chess/rooms/{self.room.id}/ready/", {"ready": True}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # host start confirm
        response = self.host_client.post(f"/api/chess/rooms/{self.room.id}/start/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)

        # guest start confirm -> game created
        response = self.guest_client.post(f"/api/chess/rooms/{self.room.id}/start/")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIsNotNone(response.data["game_id"])

        game = Game.objects.get(pk=response.data["game_id"])
        self.assertEqual(game.room.status, "playing")

        # white makes first move
        result = GameService.make_move(game.id, game.white_player, "e2e4")
        result.game.refresh_from_db()
        self.assertEqual(result.game.move_count, 1)
        self.assertEqual(result.game.current_turn, "black")

    def test_quick_match_flow(self):
        client_a = APIClient()
        client_b = APIClient()

        user_a = User.objects.create_user(
            email="quicka@test.com", nickname="빠른A", password="Pass123!"
        )
        user_b = User.objects.create_user(
            email="quickb@test.com", nickname="빠른B", password="Pass123!"
        )

        assert client_a.login(email=user_a.email, password="Pass123!")
        assert client_b.login(email=user_b.email, password="Pass123!")

        response_a = client_a.post("/api/chess/quick-match/")
        self.assertEqual(response_a.status_code, status.HTTP_200_OK)

        response_b = client_b.post("/api/chess/quick-match/")
        self.assertEqual(response_b.status_code, status.HTTP_200_OK)
        self.assertEqual(response_b.data["status"], "matched")

        game = Game.objects.filter(room_id=response_b.data["room_id"], result="playing").first()
        self.assertIsNotNone(game)

        # white makes a move
        GameService.make_move(game.id, game.white_player, "e2e4")

        # black resigns -> game ends
        GameService.resign(game.id, game.black_player)
        game.refresh_from_db()
        self.assertNotEqual(game.result, "playing")
