# Generated by Django 5.0.1 on 2024-01-25 15:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0001_initial'),
    ]

    operations = [
        migrations.DeleteModel(
            name='PacketAttackDetails',
        ),
        migrations.DeleteModel(
            name='PacketBaseInfor',
        ),
    ]