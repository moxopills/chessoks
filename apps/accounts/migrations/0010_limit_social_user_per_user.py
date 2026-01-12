from django.db import migrations, models


def assert_single_social_per_user(apps, schema_editor):
    SocialUser = apps.get_model("accounts", "SocialUser")
    duplicates = (
        SocialUser.objects.values("user_id")
        .annotate(count_id=models.Count("id"))
        .filter(count_id__gt=1)
    )
    if duplicates.exists():
        sample_ids = ", ".join(str(item["user_id"]) for item in duplicates[:5])
        raise RuntimeError(
            "Multiple social accounts per user exist; clean up before applying "
            f"this migration. Sample user_ids: {sample_ids}"
        )


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0009_add_new_email_to_email_verification_token"),
    ]

    operations = [
        migrations.RunPython(assert_single_social_per_user, migrations.RunPython.noop),
        migrations.AddConstraint(
            model_name="socialuser",
            constraint=models.UniqueConstraint(
                fields=("user",), name="uniq_social_user_per_user"
            ),
        ),
    ]
