from drf_spectacular.utils import extend_schema
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.serializers import (
    SkinListResponseSerializer,
    SkinPointHistoryResponseSerializer,
    SkinSelectRequestSerializer,
)
from apps.accounts.services import SkinService


class SkinCatalogView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: SkinListResponseSerializer}, tags=["스킨"])
    def get(self, request):
        result = SkinService.get_skin_catalog(request.user)
        return Response(result.data, status=result.status)


class SkinMeView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: SkinListResponseSerializer}, tags=["스킨"])
    def get(self, request):
        result = SkinService.get_skin_catalog(request.user)
        return Response(result.data, status=result.status)


class SkinPurchaseView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=None,
        responses={200: {"type": "object"}},
        tags=["스킨"],
    )
    def post(self, request, skin_id: int):
        result = SkinService.purchase_skin(request.user, skin_id)
        return Response(result.data, status=result.status)


class SkinSelectView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        request=SkinSelectRequestSerializer, responses={200: {"type": "object"}}, tags=["스킨"]
    )
    def post(self, request, skin_id: int):
        result = SkinService.select_skin(request.user, skin_id)
        return Response(result.data, status=result.status)


class SkinPointHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(
        responses={200: SkinPointHistoryResponseSerializer},
        tags=["스킨"],
    )
    def get(self, request):
        limit = request.query_params.get("limit", 30)
        result = SkinService.point_history(request.user, limit=limit)
        return Response(result.data, status=result.status)
