from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="Report",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "category",
                    models.CharField(
                        choices=[
                            ("cheat", "부정행위"),
                            ("abuse", "욕설/비매너"),
                            ("spam", "스팸"),
                            ("other", "기타"),
                        ],
                        default="other",
                        max_length=20,
                    ),
                ),
                ("description", models.TextField(blank=True, help_text="신고 사유")),
                (
                    "status",
                    models.CharField(
                        choices=[("pending", "처리 대기"), ("resolved", "처리 완료"), ("dismissed", "무효 처리")],
                        default="pending",
                        max_length=20,
                    ),
                ),
                ("resolution_note", models.TextField(blank=True, help_text="처리 메모")),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "reporter",
                    models.ForeignKey(
                        help_text="신고자",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="reports_made",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "resolved_by",
                    models.ForeignKey(
                        blank=True,
                        help_text="처리 관리자",
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="reports_resolved",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "target",
                    models.ForeignKey(
                        help_text="신고 대상",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="reports_received",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Report",
                "verbose_name_plural": "Reports",
                "db_table": "reports",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="report",
            index=models.Index(fields=["status", "created_at"], name="reports_status_created_idx"),
        ),
        migrations.AddIndex(
            model_name="report",
            index=models.Index(fields=["target", "status"], name="reports_target_status_idx"),
        ),
    ]
