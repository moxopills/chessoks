from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("chess", "0006_room_list_indexes"),
    ]

    operations = [
        migrations.AddField(
            model_name="room",
            name="guest_ready",
            field=models.BooleanField(default=False, help_text="게스트 준비 여부"),
        ),
        migrations.AddField(
            model_name="room",
            name="guest_start_confirmed",
            field=models.BooleanField(default=False, help_text="게스트 시작 승인"),
        ),
        migrations.AddField(
            model_name="room",
            name="host_ready",
            field=models.BooleanField(default=False, help_text="호스트 준비 여부"),
        ),
        migrations.AddField(
            model_name="room",
            name="host_start_confirmed",
            field=models.BooleanField(default=False, help_text="호스트 시작 승인"),
        ),
    ]
