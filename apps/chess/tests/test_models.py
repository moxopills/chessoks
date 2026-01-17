from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.chess.models import Game, Move, Room

User = get_user_model()


class RoomModelTestCase(TestCase):
    def setUp(self):
        self.host = User.objects.create_user(
            email="host@test.com", nickname="호스트", password="Pass123!"
        )

    def test_private_room_requires_password(self):
        room = Room(host=self.host, is_private=True, password="")
        with self.assertRaises(ValidationError):
            room.full_clean()

    def test_host_guest_cannot_match(self):
        room = Room(host=self.host, guest=self.host)
        with self.assertRaises(ValidationError):
            room.full_clean()


class GameModelTestCase(TestCase):
    def setUp(self):
        self.white = User.objects.create_user(
            email="white3@test.com", nickname="화이트3", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="black3@test.com", nickname="블랙3", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black)

    def test_game_requires_distinct_players(self):
        game = Game(room=self.room, white_player=self.white, black_player=self.white)
        with self.assertRaises(ValidationError):
            game.full_clean()


class MoveModelTestCase(TestCase):
    def setUp(self):
        self.white = User.objects.create_user(
            email="white4@test.com", nickname="화이트4", password="Pass123!"
        )
        self.black = User.objects.create_user(
            email="black4@test.com", nickname="블랙4", password="Pass123!"
        )
        self.room = Room.objects.create(host=self.white, guest=self.black)
        self.game = Game.objects.create(
            room=self.room, white_player=self.white, black_player=self.black
        )

    def test_move_invalid_square(self):
        move = Move(
            game=self.game,
            move_number=1,
            player_color="white",
            piece="P",
            from_square="z9",
            to_square="a1",
            san="e4",
            uci="e2e4",
            fen_after_move=self.game.fen,
        )
        with self.assertRaises(ValidationError):
            move.full_clean()

    def test_move_check_and_checkmate_conflict(self):
        move = Move(
            game=self.game,
            move_number=1,
            player_color="white",
            piece="P",
            from_square="e2",
            to_square="e4",
            san="e4",
            uci="e2e4",
            is_check=True,
            is_checkmate=True,
            fen_after_move=self.game.fen,
        )
        with self.assertRaises(ValidationError):
            move.full_clean()

    def test_move_number_positive(self):
        move = Move(
            game=self.game,
            move_number=0,
            player_color="white",
            piece="P",
            from_square="e2",
            to_square="e4",
            san="e4",
            uci="e2e4",
            fen_after_move=self.game.fen,
        )
        with self.assertRaises(ValidationError):
            move.full_clean()
