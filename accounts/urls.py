from django.urls import path
from django.contrib.auth import views as auth_views
from .views import register, setup_2fa, submit_scam_report, view_reports, report_detail, submit_comment, home, admin_dashboard, ban_user, unban_user
from .views import enable_user, reject_report, approve_report, make_admin, admin_dashboard, flag_report, remove_admin, \
    disable_user, view_evidence, view_all_reports, view_flagged_websites, vote_scam_report, donate, my_reports, donation_success

urlpatterns = [
    path('login/', auth_views.LoginView.as_view(template_name='accounts/login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(next_page='/'), name='logout'),
    path('register/', register, name='register'),
    #path('verify/<uidb64>/<token>/', verify_email, name='verify_email'),
    path("setup-2fa/", setup_2fa, name="setup_2fa"),
    path('view-reports/', view_reports, name='view_reports'),
    path('report/<int:report_id>/', report_detail, name='report_detail'),
    path('submit-report/', submit_scam_report, name='submit_scam_report'),
    path('report/<int:report_id>/comment/', submit_comment, name='submit_comment'),
    path('', home, name='home'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('ban-user/<int:user_id>/', ban_user, name='ban_user'),
    path('unban-user/<int:user_id>/', unban_user, name='unban_user'),
    path('make_admin/<int:user_id>/', make_admin, name='make_admin'),
    path('remove_admin/<int:user_id>/', remove_admin, name='remove_admin'),
    path('disable_user/<int:user_id>/', disable_user, name='disable_user'),
    path('enable_user/<int:user_id>/', enable_user, name='enable_user'),
    path('admin-dashboard/', admin_dashboard, name='admin_dashboard'),
    path('approve-report/<int:report_id>/', approve_report, name='approve_report'),
    path('reject-report/<int:report_id>/', reject_report, name='reject_report'),
    path('flag-report/<int:report_id>/', flag_report, name='flag_report'),
    path('view-evidence/<int:report_id>/', view_evidence, name='view_evidence'),
    path("all-reports/", view_all_reports, name="view_all_reports"),
    path("flagged-websites/", view_flagged_websites, name="view_flagged_websites"),
    path('vote/<int:report_id>/<str:vote_type>/', vote_scam_report, name='vote_scam_report'),
    path("donate/", donate, name="donate"),
    path("my-reports/", my_reports, name="my_reports"),
    path('donation-success/', donation_success, name="donation_success"),

]
