from ScamReportWebsiteV2 import settings
from .forms import CustomUserCreationForm
from django_otp.plugins.otp_totp.models import TOTPDevice
from .models import User2FA
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .forms import CommentForm, Comment
import socket
import geoip2.database
from django.contrib.auth.decorators import user_passes_test
from .models import User
import os
from PIL import Image
from PIL.ExifTags import TAGS
from pypdf import PdfReader
from django.shortcuts import render, redirect, get_object_or_404
from .models import ScamReport, ScamReportVote
from .forms import ScamReportForm
import exifread
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .utils import get_whois_info
from .utils import check_openphish  # ✅ Import the OpenPhish function
from .forms import DonationForm
from .models import Donation
from django.db.models import Sum
import uuid



PAYPAL_DONATE_LINK = "https://www.paypal.com/donate?business=YOUR_PAYPAL_EMAIL&currency_code=USD"


@login_required
def my_reports(request):
    reports = ScamReport.objects.filter(user=request.user).order_by("-submitted_at")
    return render(request, "accounts/my_reports.html", {"reports": reports})

@login_required
def user_donations(request):
    donations = Donation.objects.filter(user=request.user).order_by("-created_at")
    return render(request, "accounts/user_donations.html", {"donations": donations})


def donation_success(request, amount):
    transaction_id = str(uuid.uuid4())  # Generate a unique transaction ID

    # Save the donation to the database
    Donation.objects.create(
        user=request.user if request.user.is_authenticated else None,
        amount=amount,
        transaction_id=transaction_id,
        status="Completed"
    )

    return render(request, "accounts/donation_success.html", {"amount": amount, "transaction_id": transaction_id})


def donate(request):
    form = DonationForm()
    if request.method == "POST":
        form = DonationForm(request.POST)
        if form.is_valid():
            amount = form.cleaned_data["amount"]
            return render(request, "accounts/donate.html",
                          {"form": form, "amount": amount, "paypal_link": PAYPAL_DONATE_LINK})

    return render(request, "accounts/donate.html", {"form": form})


@login_required
def submit_scam_report(request):
    """
    Allows users to submit a scam report and checks the URL against OpenPhish.
    """
    if request.method == "POST":
        form = ScamReportForm(request.POST, request.FILES)
        if form.is_valid():
            report = form.save(commit=False)
            report.user = request.user  # Associate report with the logged-in user
            report.save()

            # ✅ Check the scam URL against OpenPhish blacklist
            if report.scam_url:
                is_blacklisted = check_openphish(report.scam_url)
                if is_blacklisted:
                    report.status = "Flagged"  # Flag the report if it's blacklisted
                    report.save()

            return redirect("view_reports")  # Redirect to reports page
    else:
        form = ScamReportForm()

    return render(request, "accounts/submit_scam_report.html", {"form": form})


def is_admin(user):
    return user.is_staff or user.is_superuser


@login_required
def submit_scam_report(request):
    if request.method == "POST":
        form = ScamReportForm(request.POST, request.FILES)
        if form.is_valid():
            report = form.save(commit=False)
            # Get WHOIS info for the reported scam URL
            whois_data = get_whois_info(report.scam_url)
            report.whois_info = whois_data  # Store WHOIS data in the database (need to update model)
            report.save()
            return redirect("view_reports")
    else:
        form = ScamReportForm()
    return render(request, "accounts/submit_scam_report.html", {"form": form})


@login_required
def vote_scam_report(request, report_id, vote_type):
    """Handles upvoting/downvoting a scam report."""
    scam_report = get_object_or_404(ScamReport, id=report_id)
    user_vote, created = ScamReportVote.objects.get_or_create(user=request.user, scam_report=scam_report)

    if not created and user_vote.vote_type == vote_type:
        return JsonResponse({"error": "You already voted this way!"}, status=400)

    # Remove existing vote if switching votes
    if not created:
        if vote_type == "upvote":
            scam_report.downvotes -= 1
            scam_report.upvotes += 1
        else:
            scam_report.upvotes -= 1
            scam_report.downvotes += 1
        user_vote.vote_type = vote_type
        user_vote.save()
    else:
        if vote_type == "upvote":
            scam_report.upvotes += 1
        else:
            scam_report.downvotes += 1
        user_vote.vote_type = vote_type
        user_vote.save()

    scam_report.update_credibility()
    return JsonResponse({"upvotes": scam_report.upvotes, "downvotes": scam_report.downvotes, "credibility": scam_report.credibility_score})


@csrf_exempt
@login_required
def vote_report(request, report_id, action):
    report = ScamReport.objects.get(id=report_id)

    if action == "upvote":
        report.credibility_score += 1
    elif action == "downvote":
        report.credibility_score -= 1

    report.save()
    return JsonResponse({"new_score": report.credibility_score})

@login_required
def view_flagged_websites(request):
    query = request.GET.get("q", "")
    filter_status = request.GET.get("status", "")

    reports = ScamReport.objects.filter(status="Flagged")

    if query:
        reports = reports.filter(scam_url__icontains=query)

    if filter_status:
        reports = reports.filter(status=filter_status)

    return render(request, "accounts/flagged_websites.html", {"reports": reports})

@login_required
def view_all_reports(request):
    reports = ScamReport.objects.all().order_by("-submitted_at")  # Show all reports
    return render(request, "accounts/all_reports.html", {"reports": reports})

@login_required
def view_evidence(request, report_id):
    report = get_object_or_404(ScamReport, id=report_id)
    evidence_path = os.path.join(settings.EVIDENCE_ROOT, str(report.evidence))

    metadata = {}

    # Extract metadata based on file type
    if report.evidence.name.lower().endswith((".jpg", ".jpeg", ".png")):
        try:
            with open(evidence_path, "rb") as image_file:
                tags = exifread.process_file(image_file)
                metadata = {tag: str(tags[tag]) for tag in tags}
        except Exception as e:
            metadata["error"] = f"Error extracting image metadata: {str(e)}"

    elif report.evidence.name.lower().endswith(".pdf"):
        try:
            with open(evidence_path, "rb") as pdf_file:
                reader = PdfReader(pdf_file)
                doc_metadata = reader.metadata
                metadata = {key: str(value) for key, value in doc_metadata.items()}
        except Exception as e:
            metadata["error"] = f"Error extracting PDF metadata: {str(e)}"

    context = {
        "report": report,
        "metadata": metadata,
        "evidence_url": report.evidence.url if report.evidence else None,
    }
    return render(request, "accounts/view_evidence.html", context)

@login_required
@user_passes_test(is_admin)
def approve_report(request, report_id):
    report = get_object_or_404(ScamReport, id=report_id)
    report.status = "Approved"
    report.save()
    messages.success(request, f"Report '{report.title}' has been approved.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def reject_report(request, report_id):
    report = get_object_or_404(ScamReport, id=report_id)
    report.status = "Rejected"
    report.save()
    messages.success(request, f"Report '{report.title}' has been rejected.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def flag_report(request, report_id):
    report = get_object_or_404(ScamReport, id=report_id)
    report.status = "Flagged"
    report.save()
    messages.success(request, f"Report '{report.title}' has been flagged for review.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def make_admin(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_staff = True
    user.save()
    messages.success(request, f"{user.username} is now an admin.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def remove_admin(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_staff = False
    user.save()
    messages.success(request, f"{user.username} is no longer an admin.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def disable_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = False
    user.save()
    messages.warning(request, f"{user.username} has been disabled.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def enable_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = True
    user.save()
    messages.success(request, f"{user.username} has been enabled.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def ban_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = False
    user.save()
    messages.success(request, f"User {user.username} has been banned.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def unban_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = True
    user.save()
    messages.success(request, f"User {user.username} has been unbanned.")
    return redirect('admin_dashboard')

@login_required
@user_passes_test(is_admin)
def admin_dashboard(request):
    pending_reports = ScamReport.objects.filter(status="Pending")
    flagged_reports = ScamReport.objects.filter(status="Flagged")
    all_reports = ScamReport.objects.all()  # Fetch all reports
    all_users = User.objects.all()

    context = {
        "pending_reports": pending_reports,
        "flagged_reports": flagged_reports,
        "all_reports": all_reports,
        "all_users": all_users,
    }
    return render(request, "accounts/admin_dashboard.html", context)


def get_country_from_ip(ip):
    """ Get country name from IP address using the local MMDB database. """

    if ip.startswith("127.") or ip == "localhost":
        return "Localhost"

    db_path = os.path.join(os.path.dirname(__file__), "data/IP-TO-COUNTRY-LITE.mmdb")

    if not os.path.exists(db_path):
        print("⚠️ IP-to-Country database not found! Make sure the MMDB is placed in the 'data/' folder.")
        return "Unknown"

    try:
        with geoip2.database.Reader(db_path) as reader:
            response = reader.country(ip)
            return response.country.name
    except Exception as e:
        print(f"⚠️ Error looking up IP {ip}: {e}")
        return "Unknown"


@login_required
def submit_comment(request, report_id):
    report = get_object_or_404(ScamReport, id=report_id)

    if request.method == "POST":
        form = CommentForm(request.POST)
        if form.is_valid():
            comment = form.save(commit=False)
            comment.user = request.user
            comment.report = report
            comment.save()
            return redirect('report_detail', report_id=report.id)  # Redirect back to the report

    else:
        form = CommentForm()

    return render(request, 'accounts/submit_comment.html', {'form': form, 'report': report})


@login_required
def report_detail(request, report_id):
    report = get_object_or_404(ScamReport, id=report_id)
    comments = Comment.objects.filter(report=report)

    print(f"Loaded report: {report.title}")  # Debugging
    print(f"Comments passed to template: {comments}")  # Debugging

    return render(request, 'accounts/report_detail.html', {'report': report, 'comments': comments})

@login_required
def view_reports(request):
    reports = ScamReport.objects.all().order_by('-submitted_at')  # Show newest first
    return render(request, 'accounts/view_reports.html', {'reports': reports})

def get_client_ip(request):
    """ Get the user's real IP address. """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def get_country_from_ip(ip):
    """ Get country from IP address using simple reverse lookup (without big APIs). """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.split('.')[-1].upper()  # This gets country code in some cases
    except:
        return "Unknown"


def extract_image_metadata(image_path):
    """Extracts EXIF metadata from an image."""
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if exif_data:
            return {TAGS.get(tag, tag): value for tag, value in exif_data.items()}
        return {}
    except Exception as e:
        print(f"Error extracting image metadata: {e}")
        return {}


def extract_pdf_metadata(pdf_path):
    """Extracts metadata from a PDF document."""
    try:
        with open(pdf_path, "rb") as f:
            pdf = PdfReader(f)
            metadata = pdf.metadata
            return {key: metadata[key] for key in metadata} if metadata else {}
    except Exception as e:
        print(f"Error extracting PDF metadata: {e}")
        return {}


@login_required
def submit_scam_report(request):
    if request.method == "POST":
        form = ScamReportForm(request.POST, request.FILES)
        if form.is_valid():
            report = form.save(commit=False)
            report.user = request.user

            # Handle metadata extraction
            if report.evidence:
                file_path = report.evidence.path
                file_ext = os.path.splitext(file_path)[-1].lower()

                if file_ext in [".jpg", ".jpeg", ".png"]:
                    report.image_metadata = extract_image_metadata(file_path)
                elif file_ext == ".pdf":
                    report.pdf_metadata = extract_pdf_metadata(file_path)

            report.fetch_whois_data()
            report.save()
            return redirect("view_reports")  # Redirect to reports page

    else:
        form = ScamReportForm()

    return render(request, "accounts/submit_scam_report.html", {"form": form})


def home(request):
    total_donations = Donation.objects.aggregate(total=Sum("amount"))["total"] or 0
    latest_donor = Donation.objects.order_by("-timestamp").first()

    return render(
        request,
        "home.html",
        {
            "total_donations": total_donations,
            "latest_donor": latest_donor,
        },
    )

def user_login(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, "Login successful!")
            return redirect('home')  # Redirect to home or dashboard
        else:
            messages.error(request, "Invalid username or password.")

    return render(request, 'accounts/login.html')


@login_required
def setup_2fa(request):
    user_2fa, created = User2FA.objects.get_or_create(user=request.user)

    if request.method == "POST":
        if "enable_2fa" in request.POST:
            device = TOTPDevice.objects.create(user=request.user, confirmed=True)
            user_2fa.totp_device = device
            user_2fa.is_2fa_enabled = True
            user_2fa.save()
        elif "disable_2fa" in request.POST:
            if user_2fa.totp_device:
                user_2fa.totp_device.delete()
            user_2fa.is_2fa_enabled = False
            user_2fa.save()

        return redirect("setup_2fa")

    return render(request, "accounts/setup_2fa.html", {"user_2fa": user_2fa})

# \\\\\ Will implement later /////
#User = get_user_model()
#def verify_email(request, uidb64, token):
#    try:
#        uid = urlsafe_base64_decode(uidb64).decode()
#        user = User.objects.get(pk=uid)
#
#        if default_token_generator.check_token(user, token):
#            user.is_active = True
#            user.save()
#            return redirect('login')  # Redirect to login after verification
#        else:
#            return HttpResponse("Invalid verification link", status=400)
#
#    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
#        return HttpResponse("Invalid verification link", status=400)


def register(request):
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # Log the user in immediately
            messages.success(request, "Registration successful! You are now logged in.")
            return redirect('login')  # Redirect to login instead of home
        else:
            messages.error(request, "Registration failed. Please correct the errors below.")

    else:
        form = CustomUserCreationForm()

    return render(request, 'accounts/register.html', {'form': form})