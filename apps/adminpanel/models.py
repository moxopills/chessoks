from django.conf import settings
from django.db import models


class Report(models.Model):
    """신고 모델"""

    CATEGORY_CHOICES = [
        ("cheat", "부정행위"),
        ("abuse", "욕설/비매너"),
        ("spam", "스팸"),
        ("other", "기타"),
    ]

    STATUS_CHOICES = [
        ("pending", "처리 대기"),
        ("resolved", "처리 완료"),
        ("dismissed", "무효 처리"),
    ]

    reporter = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="reports_made",
        help_text="신고자",
    )
    target = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="reports_received",
        help_text="신고 대상",
    )
    category = models.CharField(max_length=20, choices=CATEGORY_CHOICES, default="other")
    description = models.TextField(blank=True, help_text="신고 사유")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    resolution_note = models.TextField(blank=True, help_text="처리 메모")
    resolved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reports_resolved",
        help_text="처리 관리자",
    )
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "reports"
        verbose_name = "Report"
        verbose_name_plural = "Reports"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["status", "created_at"], name="reports_status_created_idx"),
            models.Index(fields=["target", "status"], name="reports_target_status_idx"),
        ]
