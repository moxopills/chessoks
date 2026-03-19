from rest_framework.permissions import BasePermission

from apps.core.access import AccessGuard


class IsStaff(BasePermission):
    def has_permission(self, request, view):
        return AccessGuard.is_staff(request.user)


class IsSuperuser(BasePermission):
    def has_permission(self, request, view):
        return AccessGuard.is_superuser(request.user)
