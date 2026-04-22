from django.db import migrations, models


def populate_party_member_count(apps, schema_editor):
    Party = apps.get_model("community", "Party")
    PartyMember = apps.get_model("community", "PartyMember")

    counts = {}
    for row in PartyMember.objects.values("party_id").annotate(total=models.Count("id")):
        counts[row["party_id"]] = row["total"]

    for party in Party.objects.all().only("id"):
        party.member_count = counts.get(party.id, 0)
        party.save(update_fields=["member_count"])


class Migration(migrations.Migration):
    dependencies = [
        ("community", "0005_guildnotice"),
    ]

    operations = [
        migrations.AddField(
            model_name="party",
            name="member_count",
            field=models.PositiveSmallIntegerField(default=1),
        ),
        migrations.RunPython(populate_party_member_count, migrations.RunPython.noop),
    ]
