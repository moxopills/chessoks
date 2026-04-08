from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.chess.models import Game
from apps.community.models import Party, PartyMember, TeamBattleRound
from apps.community.services.team_battle_service import TeamBattleService
from apps.notifications.models import Notification

User = get_user_model()


class TeamBattleServiceTestCase(TestCase):
    def setUp(self):
        self.host_leader = User.objects.create_user(
            email="hostleader@test.com",
            nickname="호스트장",
        )
        self.host_member2 = User.objects.create_user(
            email="host2@test.com",
            nickname="호스트2",
        )
        self.host_member3 = User.objects.create_user(
            email="host3@test.com",
            nickname="호스트3",
        )
        self.guest_leader = User.objects.create_user(
            email="guestleader@test.com",
            nickname="게스트장",
        )
        self.guest_member2 = User.objects.create_user(
            email="guest2@test.com",
            nickname="게스트2",
        )
        self.guest_member3 = User.objects.create_user(
            email="guest3@test.com",
            nickname="게스트3",
        )

        self.host_party = Party.objects.create(
            leader=self.host_leader,
            title="호스트 파티",
            lineup_locked=True,
            status=Party.Status.READY,
        )
        PartyMember.objects.create(
            party=self.host_party, user=self.host_leader, slot=1, is_ready=True
        )
        PartyMember.objects.create(
            party=self.host_party, user=self.host_member2, slot=2, is_ready=True
        )
        PartyMember.objects.create(
            party=self.host_party, user=self.host_member3, slot=3, is_ready=True
        )

        self.guest_party = Party.objects.create(
            leader=self.guest_leader,
            title="게스트 파티",
            lineup_locked=True,
            status=Party.Status.READY,
        )
        PartyMember.objects.create(
            party=self.guest_party, user=self.guest_leader, slot=1, is_ready=True
        )
        PartyMember.objects.create(
            party=self.guest_party, user=self.guest_member2, slot=2, is_ready=True
        )
        PartyMember.objects.create(
            party=self.guest_party, user=self.guest_member3, slot=3, is_ready=True
        )

    @patch(
        "apps.community.services.team_battle_service.assign_colors",
        side_effect=lambda host, guest: (host, guest),
    )
    def test_start_match_creates_round_game_and_notifications(self, _mock_assign_colors):
        match = TeamBattleService.create_party_match(self.host_leader, party_id=self.host_party.id)
        TeamBattleService.join_party_match(
            self.guest_leader,
            match_id=match.id,
            party_id=self.guest_party.id,
        )

        with self.captureOnCommitCallbacks(execute=True):
            match = TeamBattleService.start_match(self.host_leader, match_id=match.id)

        match.refresh_from_db()
        self.assertEqual(match.status, match.Status.LIVE)

        round_obj = TeamBattleRound.objects.select_related("game__room").get(
            match=match,
            round_number=1,
        )
        self.assertEqual(round_obj.status, TeamBattleRound.Status.LIVE)
        self.assertIsNotNone(round_obj.game_id)
        self.assertEqual(round_obj.game.room.status, "playing")
        self.assertEqual(round_obj.game.room.host_id, self.host_leader.id)
        self.assertEqual(round_obj.game.room.guest_id, self.guest_leader.id)

        notifications = Notification.objects.filter(
            type="room_event",
            payload__match_id=match.id,
            payload__round_id=round_obj.id,
        ).order_by("user_id")
        self.assertEqual(notifications.count(), 2)
        self.assertEqual(notifications[0].payload["url"], f"/games/{round_obj.game.room_id}/")
        self.assertEqual(notifications[1].payload["url"], f"/games/{round_obj.game.room_id}/")

    @patch(
        "apps.community.services.team_battle_service.assign_colors",
        side_effect=lambda host, guest: (host, guest),
    )
    def test_resolve_game_result_advances_to_next_round(self, _mock_assign_colors):
        match = TeamBattleService.create_party_match(self.host_leader, party_id=self.host_party.id)
        TeamBattleService.join_party_match(
            self.guest_leader,
            match_id=match.id,
            party_id=self.guest_party.id,
        )

        with self.captureOnCommitCallbacks(execute=True):
            match = TeamBattleService.start_match(self.host_leader, match_id=match.id)

        live_round = TeamBattleRound.objects.select_related("game").get(
            match=match,
            round_number=1,
        )
        game = live_round.game
        game.result = Game.Status.WHITE_WIN
        game.finished_at = timezone.now()
        game.save(update_fields=["result", "finished_at"])

        with self.captureOnCommitCallbacks(execute=True):
            TeamBattleService.resolve_game_result(game)

        live_round.refresh_from_db()
        match.refresh_from_db()
        self.assertEqual(live_round.status, TeamBattleRound.Status.FINISHED)
        self.assertEqual(live_round.result, TeamBattleRound.Result.HOST)
        self.assertEqual(match.host_remaining, 3)
        self.assertEqual(match.guest_remaining, 2)

        next_round = TeamBattleRound.objects.select_related("game__room").get(
            match=match,
            round_number=2,
        )
        self.assertEqual(next_round.status, TeamBattleRound.Status.LIVE)
        self.assertIsNotNone(next_round.game_id)
        self.assertEqual(next_round.host_participant.user_id, self.host_leader.id)
        self.assertEqual(next_round.guest_participant.user_id, self.guest_member2.id)

    @patch(
        "apps.community.services.team_battle_service.assign_colors",
        side_effect=lambda host, guest: (host, guest),
    )
    def test_manual_round_result_blocked_while_linked_game_is_live(self, _mock_assign_colors):
        match = TeamBattleService.create_party_match(self.host_leader, party_id=self.host_party.id)
        TeamBattleService.join_party_match(
            self.guest_leader,
            match_id=match.id,
            party_id=self.guest_party.id,
        )

        with self.captureOnCommitCallbacks(execute=True):
            match = TeamBattleService.start_match(self.host_leader, match_id=match.id)

        live_round = TeamBattleRound.objects.select_related("game").get(
            match=match,
            round_number=1,
        )

        with self.assertRaisesMessage(ValidationError, "연결된 실전 대국이 진행 중입니다."):
            TeamBattleService.report_round_result(
                self.host_leader,
                match_id=match.id,
                round_id=live_round.id,
                result=TeamBattleRound.Result.HOST,
            )
