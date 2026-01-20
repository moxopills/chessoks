from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("chess", "0004_alter_game_room"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LobbyMessage",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("message", models.CharField(max_length=500)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="lobby_messages",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "로비 메시지",
                "verbose_name_plural": "로비 메시지",
                "db_table": "lobby_messages",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="lobbymessage",
            index=models.Index(fields=["-created_at"], name="lobby_msg_created_idx"),
        ),
    ]
