# Generated by Django 5.0.1 on 2024-01-30 02:47

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0007_alter_packetbaseinfo_dst_port_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='packetbaseinfo',
            name='path',
            field=models.TextField(),
        ),
    ]
