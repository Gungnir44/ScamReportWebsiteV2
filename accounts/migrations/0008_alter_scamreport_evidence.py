# Generated by Django 5.1.6 on 2025-02-26 04:56

import accounts.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0007_donation_created_at_donation_status'),
    ]

    operations = [
        migrations.AlterField(
            model_name='scamreport',
            name='evidence',
            field=models.FileField(blank=True, null=True, upload_to='evidence/evidence/', validators=[accounts.models.validate_file_size]),
        ),
    ]
