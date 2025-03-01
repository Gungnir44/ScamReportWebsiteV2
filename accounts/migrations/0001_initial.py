# Generated by Django 5.1.6 on 2025-02-25 23:36

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('otp_totp', '0003_add_timestamps'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ScamReport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('submitted_at', models.DateTimeField(auto_now_add=True)),
                ('scam_website', models.URLField(blank=True, null=True)),
                ('evidence', models.FileField(blank=True, null=True, upload_to='evidence/evidence/')),
                ('credibility_score', models.FloatField(blank=True, default=0.0, null=True)),
                ('ip_address', models.GenericIPAddressField(blank=True, null=True)),
                ('country', models.CharField(blank=True, max_length=100, null=True)),
                ('status', models.CharField(choices=[('Pending', 'Pending'), ('Approved', 'Approved'), ('Rejected', 'Rejected'), ('Flagged', 'Flagged')], default='Pending', max_length=20)),
                ('image_metadata', models.JSONField(blank=True, null=True)),
                ('pdf_metadata', models.JSONField(blank=True, null=True)),
                ('scam_url', models.URLField(blank=True, null=True)),
                ('whois_info', models.TextField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to=settings.AUTH_USER_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Comment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('content', models.TextField()),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
                ('report', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='comments', to='accounts.scamreport')),
            ],
        ),
        migrations.CreateModel(
            name='User2FA',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_2fa_enabled', models.BooleanField(default=False)),
                ('totp_device', models.OneToOneField(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='otp_totp.totpdevice')),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
