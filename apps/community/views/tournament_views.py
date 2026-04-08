from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.community.serializers import (
    TournamentCreateSerializer,
    TournamentSerializer,
)
from apps.community.services import TournamentService


class TournamentListCreateView(APIView):
    def get_permissions(self):
        return [AllowAny()] if self.request.method == "GET" else [IsAuthenticated()]

    def get(self, request):
        tournaments = TournamentService.list_tournaments(request.user)
        return Response(
            {
                "count": tournaments.count(),
                "results": TournamentSerializer(
                    tournaments,
                    many=True,
                    context={"request": request},
                ).data,
            }
        )

    def post(self, request):
        serializer = TournamentCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        tournament = TournamentService.create_tournament(request.user, **serializer.validated_data)
        return Response(
            TournamentSerializer(tournament, context={"request": request}).data, status=201
        )


class TournamentRegisterView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, tournament_id: int):
        entry = TournamentService.register(request.user, tournament_id)
        return Response({"id": entry.id, "status": entry.status}, status=201)


class TournamentUnregisterView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, tournament_id: int):
        TournamentService.unregister(request.user, tournament_id)
        return Response({"status": "unregistered"})
