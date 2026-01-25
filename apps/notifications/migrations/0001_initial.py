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
            name="Notification",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "type",
                    models.CharField(
                        choices=[
                            ("friend_request", "친구 요청"),
                            ("friend_accept", "친구 수락"),
                            ("match_found", "매칭 완료"),
                            ("room_event", "방 이벤트"),
                            ("rematch", "리매치"),
                            ("game_result", "게임 결과"),
                            ("rating_change", "레이팅 변동"),
                            ("tier_promotion", "티어 승격"),
                        ],
                        max_length=30,
                    ),
                ),
                ("title", models.CharField(max_length=100)),
                ("message", models.CharField(max_length=255)),
                ("payload", models.JSONField(blank=True, default=dict)),
                ("is_read", models.BooleanField(default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notifications",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "notifications",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="notification",
            index=models.Index(fields=["user", "is_read", "created_at"], name="notif_user_read_idx"),
        ),
    ]
