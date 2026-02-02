from datetime import timedelta

from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.shortcuts import render
from django.utils import timezone
from django.views.generic import TemplateView

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.accounts.models import User
from apps.adminpanel.models import Report
from apps.adminpanel.permissions import IsStaff, IsSuperuser
from apps.adminpanel.serializers import (
    AdminStatsSerializer,
    AdminUserSerializer,
    MuteSerializer,
    NoticeSerializer,
    PromoteSerializer,
    ReportCreateSerializer,
    ReportResolveSerializer,
    ReportSerializer,
    SuspendSerializer,
)
from apps.adminpanel.services import AdminPanelService
from apps.notifications.services import NotificationService


def _format_until(until: timezone.datetime | None) -> str:
    if not until:
        return ""
    now = timezone.now()
    remaining = max(until - now, timedelta())
    total_minutes = int(remaining.total_seconds() // 60)
    hours, minutes = divmod(total_minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days:
        parts.append(f"{days}일")
    if hours:
        parts.append(f"{hours}시간")
    if minutes and not days:
        parts.append(f"{minutes}분")
    remain_text = " ".join(parts) if parts else "곧 해제"
    until_text = timezone.localtime(until).strftime("%Y-%m-%d %H:%M")
    return f"해제: {until_text} (남은 {remain_text})"


class AdminDashboardView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def get(self, request):
        return render(request, "admin/dashboard.html")


class AdminDashboardPageView(LoginRequiredMixin, UserPassesTestMixin, TemplateView):
    template_name = "admin/dashboard.html"

    def test_func(self):
        return self.request.user.is_staff


class AdminStatsView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def get(self, request):
        data = AdminPanelService.stats()
        return Response(AdminStatsSerializer(data).data)


class AdminUserListView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def get(self, request):
        query = request.query_params.get("q")
        limit = int(request.query_params.get("limit", 20))
        offset = int(request.query_params.get("offset", 0))
        total, users = AdminPanelService.list_users(query=query, limit=limit, offset=offset)
        return Response({"count": total, "results": AdminUserSerializer(users, many=True).data})


class AdminUserPromoteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperuser]

    def post(self, request, user_id: int):
        serializer = PromoteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(pk=user_id)
        user.is_staff = serializer.validated_data["is_staff"]
        user.is_superuser = serializer.validated_data["is_superuser"]
        user.save(update_fields=["is_staff", "is_superuser"])
        return Response(AdminUserSerializer(user).data)


class AdminUserSuspendView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def post(self, request, user_id: int):
        serializer = SuspendSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(pk=user_id)
        until = serializer.validated_data.get("until")
        if not until:
            until = timezone.now() + timedelta(days=serializer.validated_data["days"])
        user.suspended_until = until
        reason = serializer.validated_data.get("reason", "")
        user.suspension_reason = reason
        user.save(update_fields=["suspended_until", "suspension_reason"])
        message = "관리자에 의해 계정이 정지되었습니다."
        if reason:
            message = f"{message} (사유: {reason})"
        until_text = _format_until(user.suspended_until)
        if until_text:
            message = f"{message} · {until_text}"
        NotificationService.create_notification(
            user=user,
            type="account_suspended",
            title="계정 정지",
            message=message,
            payload={"until": user.suspended_until.isoformat(), "reason": reason},
        )
        return Response(AdminUserSerializer(user).data)


class AdminUserUnsuspendView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def post(self, request, user_id: int):
        user = User.objects.get(pk=user_id)
        user.suspended_until = None
        user.suspension_reason = ""
        user.save(update_fields=["suspended_until", "suspension_reason"])
        NotificationService.create_notification(
            user=user,
            type="account_unsuspended",
            title="계정 정지 해제",
            message="계정 정지가 해제되었습니다.",
            payload={},
        )
        return Response(AdminUserSerializer(user).data)


class AdminUserMuteView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def post(self, request, user_id: int):
        serializer = MuteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = User.objects.get(pk=user_id)
        until = serializer.validated_data.get("until")
        if not until:
            until = timezone.now() + timedelta(minutes=serializer.validated_data["minutes"])
        user.muted_until = until
        reason = serializer.validated_data.get("reason", "")
        user.mute_reason = reason
        user.save(update_fields=["muted_until", "mute_reason"])
        message = "관리자에 의해 채팅이 제한되었습니다."
        if reason:
            message = f"{message} (사유: {reason})"
        until_text = _format_until(user.muted_until)
        if until_text:
            message = f"{message} · {until_text}"
        NotificationService.create_notification(
            user=user,
            type="chat_mute",
            title="채팅 금지",
            message=message,
            payload={"until": user.muted_until.isoformat(), "reason": reason},
        )
        return Response(AdminUserSerializer(user).data)


class AdminUserUnmuteView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def post(self, request, user_id: int):
        user = User.objects.get(pk=user_id)
        user.muted_until = None
        user.mute_reason = ""
        user.save(update_fields=["muted_until", "mute_reason"])
        NotificationService.create_notification(
            user=user,
            type="chat_unmute",
            title="채팅 제한 해제",
            message="채팅 제한이 해제되었습니다.",
            payload={},
        )
        return Response(AdminUserSerializer(user).data)


class AdminUserForceDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def delete(self, request, user_id: int):
        user = User.objects.get(pk=user_id)
        user.delete()
        return Response({"message": "계정이 삭제되었습니다."}, status=status.HTTP_200_OK)


class AdminNoticeCreateView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def post(self, request):
        serializer = NoticeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        title = serializer.validated_data["title"]
        message = serializer.validated_data["message"]
        users = User.objects.filter(is_active=True).only("id")
        for user in users.iterator(chunk_size=1000):
            NotificationService.create_notification(
                user=user,
                type="admin_notice",
                title=title,
                message=message,
                payload={},
            )
        return Response({"message": "공지 발송 완료"}, status=status.HTTP_201_CREATED)


class ReportCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ReportCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target = User.objects.get(pk=serializer.validated_data["target_id"])
        report = Report.objects.create(
            reporter=request.user,
            target=target,
            category=serializer.validated_data["category"],
            description=serializer.validated_data.get("description", ""),
        )
        return Response(ReportSerializer(report).data, status=status.HTTP_201_CREATED)


class AdminReportListView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def get(self, request):
        status_filter = request.query_params.get("status")
        limit = int(request.query_params.get("limit", 20))
        offset = int(request.query_params.get("offset", 0))
        total, reports = AdminPanelService.list_reports(
            status=status_filter, limit=limit, offset=offset
        )
        data = []
        for report in reports:
            data.append(
                {
                    "id": report.id,
                    "reporter_id": report.reporter_id,
                    "reporter_nickname": report.reporter.nickname if report.reporter else "",
                    "target_id": report.target_id,
                    "target_nickname": report.target.nickname,
                    "category": report.category,
                    "description": report.description,
                    "status": report.status,
                    "resolution_note": report.resolution_note,
                    "resolved_by_id": report.resolved_by_id,
                    "resolved_at": report.resolved_at,
                    "created_at": report.created_at,
                }
            )
        return Response({"count": total, "results": data})


class AdminReportResolveView(APIView):
    permission_classes = [IsAuthenticated, IsStaff]

    def post(self, request, report_id: int):
        serializer = ReportResolveSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        report = Report.objects.select_related("target", "reporter").get(pk=report_id)
        report.mark_resolved(
            request.user,
            serializer.validated_data["status"],
            serializer.validated_data.get("resolution_note", ""),
        )
        if report.reporter:
            status_label = "처리 완료" if report.status == "resolved" else "무효 처리"
            note = report.resolution_note.strip()
            message = f"신고가 {status_label}되었습니다."
            if note:
                message = f"{message} (사유: {note})"
            NotificationService.create_notification(
                user=report.reporter,
                type="report_result_reporter",
                title="신고 처리 결과",
                message=message,
                payload={
                    "status": report.status,
                    "report_id": report.id,
                    "target_id": report.target_id,
                },
            )
        return Response(ReportSerializer(report).data)
