from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0031_alter_seasonreward_reward_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="userstats",
            name="earned_achievement_keys",
            field=models.JSONField(blank=True, default=list, help_text="달성한 업적 키 목록"),
        ),
        migrations.AddField(
            model_name="userstats",
            name="featured_achievement_key",
            field=models.CharField(
                blank=True,
                default="",
                help_text="대표 업적 키",
                max_length=40,
            ),
        ),
        migrations.AlterField(
            model_name="skinpointlog",
            name="reason",
            field=models.CharField(
                choices=[
                    ("game_win", "게임 승리"),
                    ("game_loss", "게임 패배"),
                    ("game_draw", "게임 무승부"),
                    ("skin_purchase", "스킨 구매"),
                    ("puzzle_solve", "퍼즐 클리어"),
                    ("season_reward", "시즌 보상"),
                    ("achievement_reward", "업적 달성"),
                    ("adjust", "운영자 조정"),
                ],
                max_length=50,
            ),
        ),
    ]
