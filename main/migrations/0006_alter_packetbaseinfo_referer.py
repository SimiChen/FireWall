# Generated by Django 5.0.1 on 2024-01-26 13:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0005_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='packetbaseinfo',
            name='referer',
            field=models.CharField(blank=True, max_length=100, null=True),
        ),
    ]
