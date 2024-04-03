# Generated by Django 5.0.3 on 2024-04-02 17:47

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('PastelDeNata', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='enterprise',
            name='address',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='enterprise',
            name='description',
            field=models.TextField(null=True),
        ),
        migrations.AlterField(
            model_name='enterprise',
            name='district',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='PastelDeNata.district'),
        ),
        migrations.AlterField(
            model_name='enterprise',
            name='rating_average',
            field=models.FloatField(default=0),
        ),
    ]
