from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("chess", "0008_alter_room_status"),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="room",
            name="time_limit_positive",
        ),
        migrations.AddConstraint(
            model_name="room",
            constraint=models.CheckConstraint(
                condition=models.Q(time_limit__gte=0),
                name="time_limit_nonnegative",
            ),
        ),
    ]
