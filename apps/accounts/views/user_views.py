"""사용자 인증 및 프로필 관련 View"""

from django.core.cache import cache

from drf_spectacular.utils import extend_schema
from rest_framework.generics import RetrieveAPIView, UpdateAPIView
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.throttling import AnonRateThrottle, UserRateThrottle
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.accounts.serializers import (
    AccountDeleteSerializer,
    DashboardSerializer,
    EmailChangeConfirmSerializer,
    EmailChangeRequestSerializer,
    EmailCheckSerializer,
    EmailVerificationResendSerializer,
    EmailVerificationSerializer,
    LeaderboardEntrySerializer,
    LeaderboardResponseSerializer,
    LoginRequestSerializer,
    LoginResponseSerializer,
    NicknameCheckSerializer,
    OnlineStatusListSerializer,
    OnlineStatusSerializer,
    OpponentProfileSerializer,
    PasswordChangeSerializer,
    PasswordResetConfirmSerializer,
    PasswordResetRequestSerializer,
    ProfileUpdateSerializer,
    PublicUserSerializer,
    SignupEmailConfirmSerializer,
    SignupEmailRequestSerializer,
    UserSerializer,
    UserSignUpSerializer,
)
from apps.accounts.services import (
    AccountSessionService,
    OnlineStatusService,
    RankingService,
    UserProfileService,
)
from apps.chess.serializers import GameHistorySerializer
from apps.chess.services import GameQueryService


class CurrentUserMixin:
    """현재 로그인한 유저를 stats와 함께 조회하는 Mixin"""

    def get_object(self):
        return User.objects.select_related("stats").get(pk=self.request.user.pk)


class LoginView(APIView):
    """로그인 - 3번 실패 시 5분 잠금"""

    permission_classes = [AllowAny]

    @extend_schema(
        request=LoginRequestSerializer,
        responses={200: LoginResponseSerializer},
        tags=["인증"],
    )
    def post(self, request):
        email = request.data.get("email", "").strip()
        password = request.data.get("password", "")
        result = AccountSessionService.login(request, email, password)
        return Response(result.data, status=result.status)


class LogoutView(APIView):
    """로그아웃"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=None,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        result = AccountSessionService.logout(request)
        return Response(result.data, status=result.status)


class SignUpView(APIView):
    """회원가입 - 이메일 인증 완료 후 가입"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=UserSignUpSerializer,
        responses={
            201: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "email": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = UserSignUpSerializer(data=request.data)
        result = UserProfileService.signup(serializer)
        return Response(result.data, status=result.status)


class SignupEmailRequestView(APIView):
    """회원가입 이메일 인증 요청"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=SignupEmailRequestSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "email": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = SignupEmailRequestSerializer(data=request.data)
        result = UserProfileService.signup_email_request(serializer)
        return Response(result.data, status=result.status)


class SignupEmailConfirmView(APIView):
    """회원가입 이메일 인증 확인"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=SignupEmailConfirmSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {"message": {"type": "string"}, "email": {"type": "string"}},
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = SignupEmailConfirmSerializer(data=request.data)
        result = UserProfileService.signup_email_confirm(serializer)
        return Response(result.data, status=result.status)


@extend_schema(tags=["프로필"])
class CurrentUserView(CurrentUserMixin, RetrieveAPIView):
    """현재 로그인한 유저 정보"""

    serializer_class = UserSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: UserSerializer})
    def retrieve(self, request, *args, **kwargs):
        response = super().retrieve(request, *args, **kwargs)
        response["Cache-Control"] = "private, max-age=60"
        return response


@extend_schema(tags=["프로필"])
class ProfileUpdateView(CurrentUserMixin, UpdateAPIView):
    """프로필 수정"""

    serializer_class = ProfileUpdateSerializer
    permission_classes = [IsAuthenticated]

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserSerializer})
    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data)
        UserProfileService.profile_update(serializer, user)
        return Response(UserSerializer(user).data)

    @extend_schema(request=ProfileUpdateSerializer, responses={200: UserSerializer})
    def partial_update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=True)
        UserProfileService.profile_update(serializer, user)
        return Response(UserSerializer(user).data)


class PasswordResetRequestView(APIView):
    """비밀번호 재설정 요청"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=PasswordResetRequestSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        result = UserProfileService.password_reset_request(serializer)
        return Response(result.data, status=result.status)


class PasswordResetConfirmView(APIView):
    """비밀번호 재설정 확인"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=PasswordResetConfirmSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        result = UserProfileService.password_reset_confirm(serializer)
        return Response(result.data, status=result.status)


class PasswordChangeView(APIView):
    """비밀번호 변경 (로그인 상태)"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=PasswordChangeSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["비밀번호"],
    )
    def post(self, request):
        serializer = PasswordChangeSerializer(data=request.data, context={"request": request})
        result = UserProfileService.password_change(serializer, request.user, request)
        return Response(result.data, status=result.status)


class AccountDeleteView(APIView):
    """회원 탈퇴 (Soft Delete with 유예 기간)"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=AccountDeleteSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["계정"],
    )
    def post(self, request):
        serializer = AccountDeleteSerializer(data=request.data)
        result = AccountSessionService.account_delete(serializer, request.user, request)
        return Response(result.data, status=result.status)


class EmailVerificationConfirmView(APIView):
    """이메일 인증 확인"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=EmailVerificationSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailVerificationSerializer(data=request.data)
        result = UserProfileService.email_verification_confirm(serializer)
        return Response(result.data, status=result.status)


class EmailVerificationResendView(APIView):
    """이메일 인증 재전송"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=EmailVerificationResendSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailVerificationResendSerializer(data=request.data)
        result = UserProfileService.email_verification_resend(serializer)
        return Response(result.data, status=result.status)


class UserAvatarUpdateView(APIView):
    """유저 아바타 업데이트"""

    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    @extend_schema(
        summary="아바타 이미지 업데이트",
        description="새 아바타 이미지를 업로드하고, 기존 아바타를 자동으로 삭제합니다.",
        request={
            "multipart/form-data": {
                "type": "object",
                "properties": {"avatar": {"type": "string", "format": "binary"}},
                "required": ["avatar"],
            }
        },
        responses={
            200: {
                "description": "업데이트 성공",
                "content": {
                    "application/json": {
                        "example": {
                            "message": "아바타가 성공적으로 업데이트되었습니다.",
                            "avatar_url": "https://storage.googleapis.com/chessok/avatars/uuid.png",
                        }
                    }
                },
            },
            400: {"description": "잘못된 요청"},
        },
        tags=["프로필"],
    )
    def patch(self, request):
        file = request.FILES.get("avatar")
        result = UserProfileService.avatar_update(request.user, file)
        return Response(result.data, status=result.status)

    @extend_schema(
        summary="아바타 이미지 삭제",
        description="현재 아바타 이미지를 삭제합니다.",
        responses={
            200: {
                "description": "삭제 성공",
                "content": {
                    "application/json": {"example": {"message": "아바타가 삭제되었습니다."}}
                },
            },
            400: {"description": "삭제할 아바타가 없음"},
        },
        tags=["프로필"],
    )
    def delete(self, request):
        result = UserProfileService.avatar_delete(request.user)
        return Response(result.data, status=result.status)


class EmailCheckView(APIView):
    """이메일 중복 체크"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=EmailCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "available": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = EmailCheckSerializer(data=request.data)
        result = UserProfileService.email_check(serializer)
        return Response(result.data, status=result.status)


class NicknameCheckView(APIView):
    """닉네임 중복 체크"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]

    @extend_schema(
        request=NicknameCheckSerializer,
        responses={
            200: {
                "type": "object",
                "properties": {
                    "available": {"type": "boolean"},
                    "message": {"type": "string"},
                },
            }
        },
        tags=["인증"],
    )
    def post(self, request):
        serializer = NicknameCheckSerializer(data=request.data)
        result = UserProfileService.nickname_check(serializer)
        return Response(result.data, status=result.status)


class EmailChangeRequestView(APIView):
    """이메일 변경 요청"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=EmailChangeRequestSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["계정"],
    )
    def post(self, request):
        serializer = EmailChangeRequestSerializer(data=request.data)
        result = UserProfileService.email_change_request(serializer, request.user)
        return Response(result.data, status=result.status)


class EmailChangeConfirmView(APIView):
    """이메일 변경 확인"""

    permission_classes = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    @extend_schema(
        request=EmailChangeConfirmSerializer,
        responses={200: {"type": "object", "properties": {"message": {"type": "string"}}}},
        tags=["계정"],
    )
    def post(self, request):
        serializer = EmailChangeConfirmSerializer(data=request.data)
        result = UserProfileService.email_change_confirm(serializer, request.user)
        return Response(result.data, status=result.status)


class LeaderboardView(APIView):
    """레이팅 기반 랭킹 보드 (20명씩 페이지네이션, 로그인 시 내 랭킹 포함)"""

    permission_classes = [AllowAny]
    throttle_classes = [AnonRateThrottle]
    CACHE_TTL = 60  # 1분 캐싱

    @extend_schema(
        parameters=[],
        responses={200: LeaderboardResponseSerializer},
        tags=["랭킹"],
    )
    def get(self, request):
        from apps.accounts.pagination import LeaderboardPagination

        version = RankingService.get_cache_version()
        page_num = request.query_params.get("page", "1")
        page_size = request.query_params.get("page_size", "20")
        cache_key = f"leaderboard_v{version}_p{page_num}_s{page_size}"

        cached_data = cache.get(cache_key)
        if cached_data is None:
            queryset = RankingService.get_leaderboard_queryset()
            paginator = LeaderboardPagination()
            page = paginator.paginate_queryset(queryset, request)
            cached_data = {
                "entries": LeaderboardEntrySerializer(page, many=True).data,
                "count": paginator.page.paginator.count,
                "total_pages": paginator.page.paginator.num_pages,
                "current_page": paginator.page.number,
                "next": paginator.get_next_link(),
                "previous": paginator.get_previous_link(),
            }
            cache.set(cache_key, cached_data, self.CACHE_TTL)

        my_rank = None
        if request.user.is_authenticated:
            my_rank_cache_key = f"my_rank_v{version}_{request.user.pk}"
            my_rank = cache.get(my_rank_cache_key)
            if my_rank is None:
                my_rank = RankingService.get_my_rank_data(request.user.pk)
                cache.set(my_rank_cache_key, my_rank, self.CACHE_TTL)

        return Response(
            {
                "count": cached_data["count"],
                "total_pages": cached_data["total_pages"],
                "current_page": cached_data["current_page"],
                "next": cached_data["next"],
                "previous": cached_data["previous"],
                "results": cached_data["entries"],
                "my_rank": my_rank,
            }
        )


class MyRankView(APIView):
    """내 랭킹 정보"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: LeaderboardEntrySerializer}, tags=["랭킹"])
    def get(self, request):
        user = RankingService.get_user_with_rank(request.user.pk)
        if user is None:
            return Response({"message": "유저 정보를 찾을 수 없습니다."}, status=400)
        return Response(LeaderboardEntrySerializer(user).data)


class OnlineStatusView(APIView):
    """온라인 상태 조회"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: OnlineStatusListSerializer}, tags=["유저"])
    def get(self, request):
        ids_param = request.query_params.get("ids", "")
        ids = _parse_id_list(ids_param)
        statuses = OnlineStatusService.bulk_status(ids) if ids else {}
        data = [
            OnlineStatusSerializer({"id": user_id, "online": statuses.get(user_id, False)}).data
            for user_id in ids
        ]
        return Response({"results": data})


class UserProfileView(APIView):
    """상대 프로필 + 최근 전적"""

    permission_classes = [AllowAny]
    CACHE_TTL = 300  # 5분 캐싱

    @extend_schema(responses={200: OpponentProfileSerializer}, tags=["유저"])
    def get(self, request, user_id: int):
        cache_key = f"user_profile_{user_id}"
        cached_data = cache.get(cache_key)

        user = None
        if cached_data is None:
            user = User.objects.select_related("stats").filter(pk=user_id).first()
            if user is None:
                return Response({"message": "유저 정보를 찾을 수 없습니다."}, status=404)

            recent_games = GameQueryService.list_recent_for_user(user, limit=20)
            cached_data = {
                "user": PublicUserSerializer(user).data,
                "recent_games": GameHistorySerializer(recent_games, many=True).data,
            }
            cache.set(cache_key, cached_data, self.CACHE_TTL)

        vs_summary = None
        if request.user.is_authenticated and request.user.pk != user_id:
            if user is None:
                user = User.objects.filter(pk=user_id).first()
            if user:
                vs_summary = GameQueryService.head_to_head_summary(request.user, user)

        return Response(
            {
                "user": cached_data["user"],
                "recent_games": cached_data["recent_games"],
                "vs_summary": vs_summary,
            }
        )


class UserDashboardView(APIView):
    """내 통계 대시보드"""

    permission_classes = [IsAuthenticated]

    @extend_schema(responses={200: DashboardSerializer}, tags=["통계"])
    def get(self, request):
        user = User.objects.select_related("stats").get(pk=request.user.pk)
        stats = user.stats
        recent_games = GameQueryService.list_recent_for_user(user, limit=10)
        data = {
            "user": PublicUserSerializer(user).data,
            "summary": {
                "rating": stats.rating,
                "rank_tier": stats.rank_tier,
                "games_played": stats.games_played,
                "games_won": stats.games_won,
                "games_lost": stats.games_lost,
                "games_draw": stats.games_draw,
                "win_rate": stats.win_rate,
            },
            "recent_games": GameHistorySerializer(recent_games, many=True).data,
        }
        return Response(data)


def _parse_id_list(value: str) -> list[int]:
    if not value:
        return []
    ids = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if part.isdigit():
            ids.append(int(part))
    return ids
