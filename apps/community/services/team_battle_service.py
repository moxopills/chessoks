from django.db import models, transaction
from django.db.models import Prefetch
from django.utils import timezone

from rest_framework.exceptions import ValidationError

from apps.chess.models import Game, Room
from apps.chess.utils import assign_colors
from apps.community.models import (
    Guild,
    GuildMember,
    Party,
    PartyMember,
    TeamBattleMatch,
    TeamBattleParticipant,
    TeamBattleRound,
)


class TeamBattleService:
    TEAM_BATTLE_TIME_LIMIT_MINUTES = 15
    TEAM_BATTLE_INCREMENT_SECONDS = 10

    @staticmethod
    def list_matches():
        return (
            TeamBattleMatch.objects.select_related(
                "host_party",
                "guest_party",
                "host_guild",
                "guest_guild",
            )
            .prefetch_related(
                Prefetch(
                    "participants",
                    queryset=TeamBattleParticipant.objects.select_related(
                        "user", "user__stats"
                    ).order_by("side", "order"),
                ),
                Prefetch(
                    "rounds",
                    queryset=TeamBattleRound.objects.select_related(
                        "game__room",
                        "host_participant__user",
                        "host_participant__user__stats",
                        "guest_participant__user",
                        "guest_participant__user__stats",
                    ).order_by("round_number"),
                ),
            )
            .order_by("-created_at")
        )

    @staticmethod
    @transaction.atomic
    def create_party_match(actor, *, party_id: int) -> TeamBattleMatch:
        party = Party.objects.select_for_update().get(pk=party_id)
        if party.leader_id != actor.id:
            raise ValidationError({"detail": ["파티장만 단체전 매칭을 시작할 수 있습니다."]})
        if not party.lineup_locked:
            raise ValidationError({"detail": ["라인업을 먼저 고정해주세요."]})
        if party.status in {Party.Status.QUEUED, Party.Status.BATTLING}:
            raise ValidationError({"detail": ["이미 다른 팀전에 참가 중인 파티입니다."]})
        match = TeamBattleMatch.objects.create(
            battle_type=TeamBattleMatch.BattleType.PARTY,
            host_party=party,
        )
        TeamBattleService._snapshot_party_lineup(match, TeamBattleParticipant.Side.HOST, party)
        party.status = Party.Status.QUEUED
        party.save(update_fields=["status", "updated_at"])
        return match

    @staticmethod
    @transaction.atomic
    def create_guild_match(actor, *, guild_id: int) -> TeamBattleMatch:
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        membership = GuildMember.objects.filter(guild=guild, user=actor).first()
        if not membership or membership.role not in {
            GuildMember.Role.LEADER,
            GuildMember.Role.VICE,
            GuildMember.Role.MANAGER,
        }:
            raise ValidationError({"detail": ["길드 관리 권한이 필요합니다."]})
        match = TeamBattleMatch.objects.create(
            battle_type=TeamBattleMatch.BattleType.GUILD,
            host_guild=guild,
        )
        TeamBattleService._snapshot_guild_lineup(match, TeamBattleParticipant.Side.HOST, guild)
        return match

    @staticmethod
    @transaction.atomic
    def join_party_match(actor, *, match_id: int, party_id: int) -> TeamBattleMatch:
        match = TeamBattleMatch.objects.select_for_update().get(pk=match_id)
        if match.battle_type != TeamBattleMatch.BattleType.PARTY:
            raise ValidationError({"detail": ["단체전 매치가 아닙니다."]})
        if match.guest_party_id:
            raise ValidationError({"detail": ["이미 상대 파티가 참가했습니다."]})
        party = Party.objects.select_for_update().get(pk=party_id)
        if match.host_party_id == party.id:
            raise ValidationError({"detail": ["호스트 파티는 자기 자신과 매칭할 수 없습니다."]})
        if party.leader_id != actor.id:
            raise ValidationError({"detail": ["파티장만 참가를 확정할 수 있습니다."]})
        if not party.lineup_locked:
            raise ValidationError({"detail": ["라인업을 먼저 고정해주세요."]})
        if party.status in {Party.Status.QUEUED, Party.Status.BATTLING}:
            raise ValidationError({"detail": ["이미 다른 팀전에 참가 중인 파티입니다."]})
        match.guest_party = party
        match.save(update_fields=["guest_party"])
        TeamBattleService._snapshot_party_lineup(match, TeamBattleParticipant.Side.GUEST, party)
        party.status = Party.Status.QUEUED
        party.save(update_fields=["status", "updated_at"])
        return match

    @staticmethod
    @transaction.atomic
    def join_guild_match(actor, *, match_id: int, guild_id: int) -> TeamBattleMatch:
        match = TeamBattleMatch.objects.select_for_update().get(pk=match_id)
        if match.battle_type != TeamBattleMatch.BattleType.GUILD:
            raise ValidationError({"detail": ["길드전 매치가 아닙니다."]})
        if match.guest_guild_id:
            raise ValidationError({"detail": ["이미 상대 길드가 참가했습니다."]})
        guild = Guild.objects.select_for_update().get(pk=guild_id)
        if match.host_guild_id == guild.id:
            raise ValidationError({"detail": ["호스트 길드는 자기 자신과 매칭할 수 없습니다."]})
        membership = GuildMember.objects.filter(guild=guild, user=actor).first()
        if not membership or membership.role not in {
            GuildMember.Role.LEADER,
            GuildMember.Role.VICE,
            GuildMember.Role.MANAGER,
        }:
            raise ValidationError({"detail": ["길드 관리 권한이 필요합니다."]})
        match.guest_guild = guild
        match.save(update_fields=["guest_guild"])
        TeamBattleService._snapshot_guild_lineup(match, TeamBattleParticipant.Side.GUEST, guild)
        return match

    @staticmethod
    @transaction.atomic
    def start_match(actor, *, match_id: int) -> TeamBattleMatch:
        match = TeamBattleMatch.objects.select_for_update().get(pk=match_id)
        TeamBattleService._require_host_manager(actor, match)
        if match.status != TeamBattleMatch.Status.WAITING:
            raise ValidationError({"detail": ["대기 중인 팀전만 시작할 수 있습니다."]})
        if match.battle_type == TeamBattleMatch.BattleType.PARTY and not match.guest_party_id:
            raise ValidationError({"detail": ["상대 파티가 입장해야 시작할 수 있습니다."]})
        if match.battle_type == TeamBattleMatch.BattleType.GUILD and not match.guest_guild_id:
            raise ValidationError({"detail": ["상대 길드가 입장해야 시작할 수 있습니다."]})
        host_player = TeamBattleParticipant.objects.get(
            match=match,
            side=TeamBattleParticipant.Side.HOST,
            order=1,
        )
        guest_player = TeamBattleParticipant.objects.get(
            match=match,
            side=TeamBattleParticipant.Side.GUEST,
            order=1,
        )
        round_obj = TeamBattleRound.objects.create(
            match=match,
            round_number=1,
            host_participant=host_player,
            guest_participant=guest_player,
            status=TeamBattleRound.Status.LIVE,
            started_at=timezone.now(),
        )
        TeamBattleService._create_round_game(round_obj)
        match.status = TeamBattleMatch.Status.LIVE
        match.started_at = timezone.now()
        match.save(update_fields=["status", "started_at"])
        if match.host_party_id:
            Party.objects.filter(pk=match.host_party_id).update(status=Party.Status.BATTLING)
        if match.guest_party_id:
            Party.objects.filter(pk=match.guest_party_id).update(status=Party.Status.BATTLING)
        return match

    @staticmethod
    @transaction.atomic
    def report_round_result(actor, *, match_id: int, round_id: int, result: str) -> TeamBattleMatch:
        match = TeamBattleMatch.objects.select_for_update().get(pk=match_id)
        TeamBattleService._require_host_manager(actor, match)
        round_obj = (
            TeamBattleRound.objects.select_for_update()
            .select_related(
                "host_participant",
                "guest_participant",
            )
            .get(pk=round_id, match=match, status=TeamBattleRound.Status.LIVE)
        )
        linked_game = None
        if round_obj.game_id:
            linked_game = Game.objects.only("id", "result").filter(pk=round_obj.game_id).first()
        if linked_game and linked_game.result == Game.Status.PLAYING:
            raise ValidationError(
                {
                    "detail": [
                        "연결된 실전 대국이 진행 중입니다. 게임 종료 후 결과가 자동 반영됩니다."
                    ]
                }
            )
        if result not in {
            TeamBattleRound.Result.HOST,
            TeamBattleRound.Result.GUEST,
            TeamBattleRound.Result.DRAW,
        }:
            raise ValidationError({"detail": ["유효한 라운드 결과가 아닙니다."]})
        round_obj.result = result
        round_obj.status = TeamBattleRound.Status.FINISHED
        round_obj.ended_at = timezone.now()
        round_obj.save(update_fields=["result", "status", "ended_at"])
        if result == TeamBattleRound.Result.HOST:
            TeamBattleService._handle_host_win(match, round_obj)
        elif result == TeamBattleRound.Result.GUEST:
            TeamBattleService._handle_guest_win(match, round_obj)
        else:
            TeamBattleService._handle_draw(match, round_obj)
        TeamBattleService._create_next_round_if_needed(match)
        return match

    @staticmethod
    def _handle_host_win(match: TeamBattleMatch, round_obj: TeamBattleRound) -> None:
        TeamBattleParticipant.objects.filter(pk=round_obj.host_participant_id).update(
            wins=models.F("wins") + 1
        )
        TeamBattleParticipant.objects.filter(pk=round_obj.guest_participant_id).update(
            is_eliminated=True
        )
        TeamBattleService._refresh_remaining(match)
        if match.guest_remaining == 0:
            match.status = TeamBattleMatch.Status.FINISHED
            match.winner_side = TeamBattleParticipant.Side.HOST
            match.ended_at = timezone.now()
            match.save(update_fields=["status", "winner_side", "ended_at"])
            TeamBattleService._restore_party_statuses(match)

    @staticmethod
    def _handle_guest_win(match: TeamBattleMatch, round_obj: TeamBattleRound) -> None:
        TeamBattleParticipant.objects.filter(pk=round_obj.guest_participant_id).update(
            wins=models.F("wins") + 1
        )
        TeamBattleParticipant.objects.filter(pk=round_obj.host_participant_id).update(
            is_eliminated=True
        )
        TeamBattleService._refresh_remaining(match)
        if match.host_remaining == 0:
            match.status = TeamBattleMatch.Status.FINISHED
            match.winner_side = TeamBattleParticipant.Side.GUEST
            match.ended_at = timezone.now()
            match.save(update_fields=["status", "winner_side", "ended_at"])
            TeamBattleService._restore_party_statuses(match)

    @staticmethod
    def _handle_draw(match: TeamBattleMatch, round_obj: TeamBattleRound) -> None:
        TeamBattleParticipant.objects.filter(
            pk__in=[round_obj.host_participant_id, round_obj.guest_participant_id]
        ).update(is_eliminated=True)
        TeamBattleService._refresh_remaining(match)
        if match.host_remaining == 0 and match.guest_remaining == 0:
            match.status = TeamBattleMatch.Status.FINISHED
            match.winner_side = "draw"
            match.ended_at = timezone.now()
            match.save(update_fields=["status", "winner_side", "ended_at"])
            TeamBattleService._restore_party_statuses(match)

    @staticmethod
    def _create_next_round_if_needed(match: TeamBattleMatch) -> None:
        if match.status == TeamBattleMatch.Status.FINISHED:
            return
        next_host = TeamBattleService._next_alive_participant(
            match, TeamBattleParticipant.Side.HOST
        )
        next_guest = TeamBattleService._next_alive_participant(
            match, TeamBattleParticipant.Side.GUEST
        )
        if not next_host or not next_guest:
            match.status = TeamBattleMatch.Status.FINISHED
            if not next_host and next_guest:
                match.winner_side = TeamBattleParticipant.Side.GUEST
            elif not next_guest and next_host:
                match.winner_side = TeamBattleParticipant.Side.HOST
            else:
                match.winner_side = "draw"
            match.ended_at = timezone.now()
            match.save(update_fields=["status", "winner_side", "ended_at"])
            TeamBattleService._restore_party_statuses(match)
            return
        if TeamBattleRound.objects.filter(match=match, status=TeamBattleRound.Status.LIVE).exists():
            return
        round_obj = TeamBattleRound.objects.create(
            match=match,
            round_number=TeamBattleRound.objects.filter(match=match).count() + 1,
            host_participant=next_host,
            guest_participant=next_guest,
            status=TeamBattleRound.Status.LIVE,
            started_at=timezone.now(),
        )
        TeamBattleService._create_round_game(round_obj)

    @staticmethod
    def _refresh_remaining(match: TeamBattleMatch) -> None:
        match.host_remaining = TeamBattleParticipant.objects.filter(
            match=match,
            side=TeamBattleParticipant.Side.HOST,
            is_eliminated=False,
        ).count()
        match.guest_remaining = TeamBattleParticipant.objects.filter(
            match=match,
            side=TeamBattleParticipant.Side.GUEST,
            is_eliminated=False,
        ).count()
        match.save(update_fields=["host_remaining", "guest_remaining"])

    @staticmethod
    def _next_alive_participant(match: TeamBattleMatch, side: str):
        return (
            TeamBattleParticipant.objects.filter(match=match, side=side, is_eliminated=False)
            .order_by("order")
            .first()
        )

    @staticmethod
    def _snapshot_party_lineup(match: TeamBattleMatch, side: str, party: Party) -> None:
        members = list(
            PartyMember.objects.filter(party=party, slot__isnull=False)
            .select_related("user")
            .order_by("slot")
        )
        if len(members) != 3:
            raise ValidationError({"detail": ["3명의 라인업이 모두 지정되어야 합니다."]})
        for member in members:
            TeamBattleParticipant.objects.create(
                match=match,
                side=side,
                order=member.slot,
                user=member.user,
                source_party=party,
            )

    @staticmethod
    def _snapshot_guild_lineup(match: TeamBattleMatch, side: str, guild: Guild) -> None:
        members = list(
            GuildMember.objects.filter(guild=guild)
            .select_related("user")
            .order_by("role", "joined_at")[:3]
        )
        if len(members) < 3:
            raise ValidationError({"detail": ["길드전은 최소 3명의 멤버가 필요합니다."]})
        for index, member in enumerate(members, start=1):
            TeamBattleParticipant.objects.create(
                match=match,
                side=side,
                order=index,
                user=member.user,
                source_guild=guild,
            )

    @staticmethod
    def _require_host_manager(actor, match: TeamBattleMatch) -> None:
        if match.battle_type == TeamBattleMatch.BattleType.PARTY:
            if match.host_party and match.host_party.leader_id == actor.id:
                return
            raise ValidationError({"detail": ["호스트 파티장만 매치를 제어할 수 있습니다."]})
        membership = GuildMember.objects.filter(guild=match.host_guild, user=actor).first()
        if not membership or membership.role not in {
            GuildMember.Role.LEADER,
            GuildMember.Role.VICE,
            GuildMember.Role.MANAGER,
        }:
            raise ValidationError({"detail": ["호스트 길드 운영진만 매치를 제어할 수 있습니다."]})

    @staticmethod
    def _restore_party_statuses(match: TeamBattleMatch) -> None:
        if match.host_party_id:
            Party.objects.filter(pk=match.host_party_id).update(status=Party.Status.READY)
        if match.guest_party_id:
            Party.objects.filter(pk=match.guest_party_id).update(status=Party.Status.READY)

    @staticmethod
    def _create_round_game(round_obj: TeamBattleRound) -> Game:
        room = Room.objects.create(
            room_type="custom",
            title=f"팀전 {round_obj.match_id} · {round_obj.round_number}라운드",
            host=round_obj.host_participant.user,
            guest=round_obj.guest_participant.user,
            status="playing",
            is_private=False,
            allow_spectators=True,
            host_ready=True,
            guest_ready=True,
            host_start_confirmed=True,
            guest_start_confirmed=True,
            time_limit=TeamBattleService.TEAM_BATTLE_TIME_LIMIT_MINUTES,
            increment_seconds=TeamBattleService.TEAM_BATTLE_INCREMENT_SECONDS,
            started_at=timezone.now(),
        )
        white_player, black_player = assign_colors(room.host, room.guest)
        game = Game.objects.create(
            room=room,
            white_player=white_player,
            black_player=black_player,
            started_at=timezone.now(),
            turn_started_at=timezone.now(),
        )
        round_obj.game = game
        round_obj.save(update_fields=["game"])
        transaction.on_commit(
            lambda: TeamBattleService._notify_round_created(round_obj, room, game)
        )
        return game

    @staticmethod
    @transaction.atomic
    def resolve_game_result(game: Game) -> TeamBattleMatch | None:
        round_obj = (
            TeamBattleRound.objects.select_for_update()
            .select_related(
                "match",
                "host_participant",
                "guest_participant",
            )
            .filter(game=game, status=TeamBattleRound.Status.LIVE)
            .first()
        )
        if not round_obj:
            return None
        match = TeamBattleMatch.objects.select_for_update().get(pk=round_obj.match_id)
        result = TeamBattleService._result_from_game(round_obj, game)
        round_obj.result = result
        round_obj.status = TeamBattleRound.Status.FINISHED
        round_obj.ended_at = game.finished_at or timezone.now()
        round_obj.save(update_fields=["result", "status", "ended_at"])
        if result == TeamBattleRound.Result.HOST:
            TeamBattleService._handle_host_win(match, round_obj)
        elif result == TeamBattleRound.Result.GUEST:
            TeamBattleService._handle_guest_win(match, round_obj)
        else:
            TeamBattleService._handle_draw(match, round_obj)
        TeamBattleService._create_next_round_if_needed(match)
        return match

    @staticmethod
    def _result_from_game(round_obj: TeamBattleRound, game: Game) -> str:
        host_user_id = round_obj.host_participant.user_id
        guest_user_id = round_obj.guest_participant.user_id
        white_win_results = {
            Game.Status.WHITE_WIN,
            Game.Status.CHECKMATE_WHITE,
            Game.Status.TIMEOUT_BLACK,
            Game.Status.RESIGNATION_BLACK,
        }
        black_win_results = {
            Game.Status.BLACK_WIN,
            Game.Status.CHECKMATE_BLACK,
            Game.Status.TIMEOUT_WHITE,
            Game.Status.RESIGNATION_WHITE,
        }
        if game.result in white_win_results:
            return (
                TeamBattleRound.Result.HOST
                if game.white_player_id == host_user_id
                else TeamBattleRound.Result.GUEST
            )
        if game.result in black_win_results:
            return (
                TeamBattleRound.Result.HOST
                if game.black_player_id == host_user_id
                else TeamBattleRound.Result.GUEST
            )
        if host_user_id == guest_user_id:
            return TeamBattleRound.Result.DRAW
        return TeamBattleRound.Result.DRAW

    @staticmethod
    def _notify_round_created(round_obj: TeamBattleRound, room: Room, game: Game) -> None:
        from apps.notifications.services import NotificationService

        title = f"팀전 {round_obj.round_number}라운드 시작"
        message = f"{round_obj.round_number}라운드 대국이 준비되었습니다."
        payload = {
            "room_id": room.id,
            "game_id": game.id,
            "match_id": round_obj.match_id,
            "round_id": round_obj.id,
            "url": f"/games/{room.id}/",
        }
        NotificationService.create_notification(
            user=round_obj.host_participant.user,
            type="room_event",
            title=title,
            message=message,
            payload=payload,
        )
        NotificationService.create_notification(
            user=round_obj.guest_participant.user,
            type="room_event",
            title=title,
            message=message,
            payload=payload,
        )
