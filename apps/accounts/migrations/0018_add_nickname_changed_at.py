from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0017_add_user_sanctions"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="nickname_changed_at",
            field=models.DateTimeField(blank=True, help_text="마지막 닉네임 변경 시간", null=True),
        ),
    ]
