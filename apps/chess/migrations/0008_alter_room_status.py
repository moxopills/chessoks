from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("chess", "0007_room_ready_flags"),
    ]

    operations = [
        migrations.AlterField(
            model_name="room",
            name="status",
            field=models.CharField(
                choices=[
                    ("waiting", "대기 중"),
                    ("ready", "준비 중"),
                    ("playing", "게임 중"),
                    ("finished", "종료"),
                ],
                default="waiting",
                help_text="방 상태",
                max_length=20,
            ),
        ),
    ]
