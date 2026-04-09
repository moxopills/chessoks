from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("community", "0002_teambattleparticipant_teambattleround_guildauditlog_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="boardcomment",
            name="like_count",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.CreateModel(
            name="BoardCommentLike",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "comment",
                    models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="likes", to="community.boardcomment"),
                ),
                (
                    "user",
                    models.ForeignKey(on_delete=models.deletion.CASCADE, related_name="board_comment_likes", to=settings.AUTH_USER_MODEL),
                ),
            ],
            options={
                "db_table": "board_comment_likes",
            },
        ),
        migrations.AddConstraint(
            model_name="boardcommentlike",
            constraint=models.UniqueConstraint(fields=("comment", "user"), name="uniq_board_comment_like"),
        ),
    ]
