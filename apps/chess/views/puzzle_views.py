from drf_spectacular.utils import extend_schema
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.permissions import IsAuthenticatedOrGuest
from apps.chess.serializers.puzzle_serializers import (
    PuzzleDailyResponseSerializer,
    PuzzleHintResponseSerializer,
    PuzzleMoveRequestSerializer,
    PuzzleMoveResponseSerializer,
    PuzzleSolutionResponseSerializer,
    PuzzleStatsResponseSerializer,
    PuzzleStreakResponseSerializer,
)
from apps.chess.services.puzzle_service import PuzzleService


class DailyPuzzleView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PuzzleDailyResponseSerializer}, tags=["퍼즐"])
    def get(self, request):
        level = request.query_params.get("level")
        daily, attempt = PuzzleService.get_daily_with_attempt(request.user, level=level)
        return Response(
            PuzzleService.serialize_daily_payload(daily=daily, attempt=attempt, user=request.user)
        )


class DailyPuzzleMoveView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(
        request=PuzzleMoveRequestSerializer,
        responses={200: PuzzleMoveResponseSerializer},
        tags=["퍼즐"],
    )
    def post(self, request):
        serializer = PuzzleMoveRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = PuzzleService.submit_move(
            user=request.user,
            move_uci=serializer.validated_data["move"],
            level=serializer.validated_data.get("level"),
        )
        return Response(result)


class DailyPuzzleHintView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PuzzleHintResponseSerializer}, tags=["퍼즐"])
    def post(self, request):
        level = request.data.get("level")
        return Response(PuzzleService.request_hint(user=request.user, level=level))


class DailyPuzzleSolutionView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PuzzleSolutionResponseSerializer}, tags=["퍼즐"])
    def get(self, request):
        level = request.query_params.get("level")
        return Response(PuzzleService.get_solution(user=request.user, level=level))


class PuzzleStatsView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PuzzleStatsResponseSerializer}, tags=["퍼즐"])
    def get(self, request):
        return Response(PuzzleService.get_stats(user=request.user))


class PuzzleStreakView(APIView):
    permission_classes = [IsAuthenticatedOrGuest]

    @extend_schema(responses={200: PuzzleStreakResponseSerializer}, tags=["퍼즐"])
    def get(self, request):
        return Response(PuzzleService.get_streak(user=request.user))
