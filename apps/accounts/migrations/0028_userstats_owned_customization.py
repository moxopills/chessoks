from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0027_skin_userstats_selected_board_skin_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="userstats",
            name="owned_nickname_colors",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="구매해 보유 중인 닉네임 색상 키 목록",
            ),
        ),
        migrations.AddField(
            model_name="userstats",
            name="owned_profile_borders",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="구매해 보유 중인 프로필 테두리 키 목록",
            ),
        ),
    ]
