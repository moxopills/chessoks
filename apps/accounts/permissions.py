"""커스텀 권한 클래스"""

from rest_framework.permissions import BasePermission

from apps.accounts.services.guest_session_service import GuestSessionService


class IsAuthenticatedOrGuest(BasePermission):
    """인증된 사용자 또는 게스트 세션이 있는 경우 허용

    게스트의 경우 임시 User를 생성하여 request.user에 설정합니다.
    """

    def has_permission(self, request, view):
        # 이미 인증된 유저
        if request.user and request.user.is_authenticated:
            return True

        # 게스트 세션 확인
        guest = getattr(request, "guest", None)
        if guest and not GuestSessionService.is_expired(guest):
            guest_user = GuestSessionService.get_or_create_user(guest)
            # request.user에 설정
            request.user = guest_user
            request._guest_session = guest
            return True

        return False
