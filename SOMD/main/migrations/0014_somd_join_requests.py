# Generated by Django 4.2.1 on 2023-06-24 03:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('main', '0013_joinrequest_writer'),
    ]

    operations = [
        migrations.AddField(
            model_name='somd',
            name='join_requests',
            field=models.ManyToManyField(blank=True, related_name='join_requests', to='main.joinrequest'),
        ),
    ]
