# Generated by Django 4.0.4 on 2022-05-24 19:44

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('board', '0001_initial'),
    ]

    operations = [
        migrations.RenameModel(
            old_name='hosts',
            new_name='host',
        ),
    ]