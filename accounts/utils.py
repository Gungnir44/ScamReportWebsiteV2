from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.urls import reverse
import whois
import requests
from .models import ScamReport


# OpenPhish database URL
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"


def check_openphish(scam_url):
    """
    Checks a scam URL against OpenPhish's phishing database.
    """
    try:
        # Fetch OpenPhish phishing URLs
        response = requests.get(OPENPHISH_FEED_URL)
        if response.status_code == 200:
            phishing_urls = response.text.split("\n")  # Convert to list

            is_blacklisted = scam_url in phishing_urls

            # Update the ScamReport entry if found
            scam_report = ScamReport.objects.filter(scam_url=scam_url).first()
            if scam_report:
                scam_report.is_blacklisted = is_blacklisted
                scam_report.blacklist_details = {"source": "OpenPhish"}
                scam_report.save()

            return is_blacklisted
    except Exception as e:
        print(f"Error checking OpenPhish: {e}")

    return False


def get_whois_info(domain):
    """
    Retrieves WHOIS information for a given domain.
    """
    try:
        domain_info = whois.whois(domain)
        return {
            "domain_name": domain_info.domain_name,
            "creation_date": domain_info.creation_date,
            "expiration_date": domain_info.expiration_date,
            "registrar": domain_info.registrar,
            "name_servers": domain_info.name_servers,
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {str(e)}"}


# \\\\\This addition will be implemented in future use /////

#def send_verification_email(request, user):
#    token = default_token_generator.make_token(user)
#    uid = urlsafe_base64_encode(force_bytes(user.pk))
#    verification_link = request.build_absolute_uri(reverse('verify_email', kwargs={'uidb64': uid, 'token': token}))

#    subject = "Verify Your Email"
#    message = render_to_string('accounts/email_verification.html', {
#        'user': user,
#        'verification_link': verification_link,
#    })

#    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email])
