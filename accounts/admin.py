from django.contrib import admin
from .models import ScamReport, Comment
from django.contrib.auth.models import User
from django.utils.html import format_html
from .models import Donation


@admin.register(Donation)
class DonationAdmin(admin.ModelAdmin):
    list_display = ("user", "amount", "transaction_id", "timestamp")
    search_fields = ("user__username", "transaction_id")
    search_fields = ("transaction_id", "user__username")

    def total_donations(self):
        return f"${sum(d.amount for d in Donation.objects.all())}"

    total_donations.short_description = "Total Donations"


@admin.register(ScamReport)  # ✅ This is the correct way to register ScamReport
class ScamReportAdmin(admin.ModelAdmin):
    list_display = ('title', 'user', 'submitted_at', 'status', 'view_evidence', 'scam_url_link', 'whois_info', 'domain_age', 'blacklist_status', 'scam_url', 'credibility_score')
    list_filter = ('status', 'submitted_at', 'scam_url')
    search_fields = ('title', 'description', 'user__username', 'scam_url', 'text')
    actions = ['approve_reports', 'reject_reports', 'flag_reports']
    ordering = ('-submitted_at',)  # Show newest reports first
    readonly_fields = ('submitted_at',)  # Prevent admins from modifying timestamps

    def approve_reports(self, request, queryset):
        queryset.update(status='Approved')
        self.message_user(request, "Selected reports have been approved.")

    def reject_reports(self, request, queryset):
        queryset.update(status='Rejected')
        self.message_user(request, "Selected reports have been rejected.")

    def flag_reports(self, request, queryset):
        queryset.update(status='Flagged')
        self.message_user(request, "Selected reports have been flagged.")

    def view_evidence(self, obj):
        if obj.evidence:
            return format_html('<a href="{}" target="_blank">View Evidence</a>', obj.evidence.url)
        return "No Evidence"
    view_evidence.short_description = "Evidence"

    def scam_url_link(self, obj):
        if obj.scam_url:
            return format_html('<a href="{}" target="_blank">{}</a>', obj.scam_url, obj.scam_url)
        return "No URL Provided"
    scam_url_link.short_description = "Scam Website"

    approve_reports.short_description = "Approve selected reports"
    reject_reports.short_description = "Reject selected reports"
    flag_reports.short_description = "Flag selected reports for review"


@admin.register(Comment)
class CommentAdmin(admin.ModelAdmin):
    list_display = ('user', 'report', 'created_at', 'content')  # Updated field name
    search_fields = ('user__username', 'report__title', 'content')


admin.site.unregister(User)
@admin.register(User)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('username', 'email', 'is_active', 'is_staff', 'date_joined', 'ban_user')
    list_filter = ('is_active', 'is_staff')
    search_fields = ('username', 'email')
    actions = ['ban_selected_users', 'unban_selected_users']

    def ban_user(self, obj):
        return "Banned" if not obj.is_active else "Active"
    ban_user.short_description = "Status"

    def ban_selected_users(self, request, queryset):
        queryset.update(is_active=False)
        self.message_user(request, "Selected users have been banned.")

    def unban_selected_users(self, request, queryset):
        queryset.update(is_active=True)
        self.message_user(request, "Selected users have been unbanned.")

    ban_selected_users.short_description = "Ban selected users"
    unban_selected_users.short_description = "Unban selected users"
