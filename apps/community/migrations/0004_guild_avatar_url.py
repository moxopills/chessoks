from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("community", "0003_boardcomment_like_count_and_likes"),
    ]

    operations = [
        migrations.AddField(
            model_name="guild",
            name="avatar_url",
            field=models.URLField(blank=True, max_length=500, null=True),
        ),
    ]
