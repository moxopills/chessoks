from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0020_alter_socialuser_provider"),
    ]

    operations = [
        migrations.AddField(
            model_name="userstats",
            name="competitive_games_played",
            field=models.IntegerField(default=0, help_text="경쟁전 게임 수"),
        ),
        migrations.AddField(
            model_name="userstats",
            name="competitive_won",
            field=models.IntegerField(default=0, help_text="경쟁전 승리 수"),
        ),
        migrations.AddField(
            model_name="userstats",
            name="competitive_lost",
            field=models.IntegerField(default=0, help_text="경쟁전 패배 수"),
        ),
        migrations.AddField(
            model_name="userstats",
            name="competitive_draw",
            field=models.IntegerField(default=0, help_text="경쟁전 무승부 수"),
        ),
        migrations.AddField(
            model_name="userstats",
            name="win_streak",
            field=models.IntegerField(default=0, help_text="연승 수"),
        ),
        migrations.AddField(
            model_name="userstats",
            name="lose_streak",
            field=models.IntegerField(default=0, help_text="연패 수"),
        ),
        migrations.AddConstraint(
            model_name="userstats",
            constraint=models.CheckConstraint(
                condition=models.Q(competitive_games_played__gte=0),
                name="stats_competitive_games_played_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="userstats",
            constraint=models.CheckConstraint(
                condition=models.Q(competitive_won__gte=0),
                name="stats_competitive_won_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="userstats",
            constraint=models.CheckConstraint(
                condition=models.Q(competitive_lost__gte=0),
                name="stats_competitive_lost_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="userstats",
            constraint=models.CheckConstraint(
                condition=models.Q(competitive_draw__gte=0),
                name="stats_competitive_draw_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="userstats",
            constraint=models.CheckConstraint(
                condition=models.Q(win_streak__gte=0),
                name="stats_win_streak_positive",
            ),
        ),
        migrations.AddConstraint(
            model_name="userstats",
            constraint=models.CheckConstraint(
                condition=models.Q(lose_streak__gte=0),
                name="stats_lose_streak_positive",
            ),
        ),
    ]
