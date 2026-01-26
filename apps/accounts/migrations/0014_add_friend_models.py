from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0013_update_stats_ranking_index"),
    ]

    operations = [
        migrations.CreateModel(
            name="Friend",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "friend",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="friends_of",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="friends",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "friends",
            },
        ),
        migrations.CreateModel(
            name="FriendRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "from_user",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="friend_requests_sent",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "to_user",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="friend_requests_received",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "friend_requests",
            },
        ),
        migrations.AddConstraint(
            model_name="friend",
            constraint=models.UniqueConstraint(fields=("user", "friend"), name="uniq_friend_pair"),
        ),
        migrations.AddConstraint(
            model_name="friend",
            constraint=models.CheckConstraint(
                condition=~models.Q(user=models.F("friend")),
                name="friend_no_self",
            ),
        ),
        migrations.AddIndex(
            model_name="friend",
            index=models.Index(fields=["user", "created_at"], name="friend_user_created_idx"),
        ),
        migrations.AddConstraint(
            model_name="friendrequest",
            constraint=models.UniqueConstraint(
                fields=("from_user", "to_user"), name="uniq_friend_request"
            ),
        ),
        migrations.AddConstraint(
            model_name="friendrequest",
            constraint=models.CheckConstraint(
                condition=~models.Q(from_user=models.F("to_user")),
                name="friend_request_no_self",
            ),
        ),
        migrations.AddIndex(
            model_name="friendrequest",
            index=models.Index(fields=["to_user", "created_at"], name="friend_request_to_idx"),
        ),
        migrations.AddIndex(
            model_name="friendrequest",
            index=models.Index(fields=["from_user", "created_at"], name="friend_request_from_idx"),
        ),
    ]
