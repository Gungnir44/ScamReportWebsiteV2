from django.db import models
from django.contrib.auth.models import User
from django_otp.plugins.otp_totp.models import TOTPDevice
import json
import whois
from datetime import datetime
from django.utils import timezone
from django.core.exceptions import ValidationError


def validate_file_size(value):
    max_size = 5 * 1024 * 1024  # 5MB
    if value.size > max_size:
        raise ValidationError("File size exceeds the 5MB limit.")

class User2FA(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    totp_device = models.OneToOneField(TOTPDevice, on_delete=models.CASCADE, null=True, blank=True)
    is_2fa_enabled = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - 2FA: {'Enabled' if self.is_2fa_enabled else 'Disabled'}"


class ScamReport(models.Model):
    STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Flagged', 'Flagged'),
    ]

    title = models.CharField(max_length=255)
    description = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    scam_website = models.URLField(blank=True, null=True)
    evidence = models.FileField(upload_to='evidence/evidence/', validators=[validate_file_size], blank=True, null=True)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="reports")

    # Upvote and downvote creditablilty
    credibility_score = models.FloatField(default=0.0, null=True, blank=True)
    upvotes = models.PositiveIntegerField(default=0)
    downvotes = models.PositiveIntegerField(default=0)

    ip_address = models.GenericIPAddressField(blank=True, null=True)
    country = models.CharField(max_length=100, blank=True, null=True)

    # New Field for Approval System
    status = models.CharField(max_length=20, choices=[("Approved", "Approved"), ("Flagged", "Flagged"), ("Rejected", "Rejected")])

    # Metadata fields
    image_metadata = models.JSONField(blank=True, null=True)  # Stores EXIF data
    pdf_metadata = models.JSONField(blank=True, null=True)    # Stores PDF metadata

    # WHOIS data
    scam_url = models.URLField(blank=True, null=True)  # Allow it to be empty
    whois_info = models.TextField(null=True, blank=True)  # Store as text instead of JSON
    blacklist_status = models.BooleanField(default=False)  # If the URL is on a scam blacklist
    domain_age = models.IntegerField(null=True, blank=True)  # Store domain age in days
    is_blacklisted = models.BooleanField(default=False)  # New Field
    blacklist_details = models.JSONField(null=True, blank=True)  # Stores API response

    def formatted_whois(self):
        return json.dumps(self.whois_info, indent=4)  # Format for display

    def fetch_whois_data(self):
        """Retrieve WHOIS data and calculate domain age"""
        try:
            domain = whois.whois(self.scam_url)
            creation_date = domain.creation_date
            if isinstance(creation_date, list):  # Sometimes it's a list
                creation_date = creation_date[0]

            if creation_date:
                self.domain_age = (datetime.now() - creation_date).days

            self.whois_info = domain
            self.save()
        except Exception as e:
            print(f"WHOIS lookup failed: {e}")

    def update_credibility(self):
        """Calculate credibility score as (upvotes - downvotes)"""
        self.credibility_score = self.upvotes - self.downvotes
        self.save()

    def __str__(self):
        return f"{self.title} ({self.status})"

class Comment(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    report = models.ForeignKey(ScamReport, on_delete=models.CASCADE, related_name="comments")
    created_at = models.DateTimeField(auto_now_add=True)
    content = models.TextField()  # This is likely the correct field name

    def __str__(self):
        return f"Comment by {self.user.username} on {self.report.title}"


class ScamReportVote(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    scam_report = models.ForeignKey(ScamReport, on_delete=models.CASCADE)
    vote_type = models.CharField(max_length=10, choices=[('upvote', 'Upvote'), ('downvote', 'Downvote')])

    class Meta:
        unique_together = ('user', 'scam_report')  # Prevent duplicate votes

    def __str__(self):
        return f"{self.user.username} - {self.vote_type} on {self.scam_report.title}"

class Donation(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    transaction_id = models.CharField(max_length=100, unique=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=20, choices=[("Pending", "Pending"), ("Completed", "Completed"), ("Failed", "Failed")], default="Pending")
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"${self.amount} - {self.user.username if self.user else 'Anonymous'}"