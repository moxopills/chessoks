from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("chess", "0011_aidifficultysetting_alter_room_room_type"),
    ]

    operations = [
        migrations.AlterField(
            model_name="room",
            name="room_type",
            field=models.CharField(
                choices=[
                    ("quick", "빠른 대전"),
                    ("random", "랜덤 대전"),
                    ("custom", "사용자 방"),
                    ("ai_easy", "AI 대전(쉬움)"),
                    ("ai_medium", "AI 대전(중간)"),
                    ("ai_hard", "AI 대전(어려움)"),
                ],
                default="custom",
                help_text="빠른 대전 또는 사용자 방",
                max_length=10,
            ),
        ),
    ]
