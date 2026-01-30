from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0016_add_code_hash_attempts_to_signup_email_token"),
    ]

    operations = [
        migrations.AddField(
            model_name="user",
            name="suspended_until",
            field=models.DateTimeField(blank=True, help_text="계정 정지 종료 시각", null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="suspension_reason",
            field=models.CharField(blank=True, help_text="정지 사유", max_length=200),
        ),
        migrations.AddField(
            model_name="user",
            name="muted_until",
            field=models.DateTimeField(blank=True, help_text="채팅 금지 종료 시각", null=True),
        ),
        migrations.AddField(
            model_name="user",
            name="mute_reason",
            field=models.CharField(blank=True, help_text="채팅 금지 사유", max_length=200),
        ),
    ]
