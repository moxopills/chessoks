from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("chess", "0005_lobby_message"),
    ]

    operations = [
        migrations.AddIndex(
            model_name="room",
            index=models.Index(fields=["is_private", "status", "room_type"], name="room_list_idx"),
        ),
    ]
