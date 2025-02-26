from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm
from .models import ScamReport
from .models import Comment
from django.core.validators import URLValidator
from django.utils.html import escape
from django.core.exceptions import ValidationError


def validate_file_extension(value):
    allowed_extensions = [".png", ".jpg", ".jpeg", ".pdf"]
    if not any(value.name.lower().endswith(ext) for ext in allowed_extensions):
        raise ValidationError("Unsupported file type. Allowed: PNG, JPG, JPEG, PDF")

class DonationForm(forms.Form):
    amount = forms.DecimalField(max_digits=10, decimal_places=2, label="Donation Amount ($)")
    def clean_text(self):
        return escape(self.cleaned_data["text"])

class CommentForm(forms.ModelForm):
    class Meta:
        model = Comment
        fields = ['content']
        widgets = {
            'content': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }
    def clean_text(self):
        return escape(self.cleaned_data["text"])


class ScamReportForm(forms.ModelForm):
    evidence = forms.FileField(validators=[validate_file_extension], required=False)

    class Meta:
        model = ScamReport
        fields = ["title", "description", "scam_url", "evidence"]

    def clean_title(self):
        return escape(self.cleaned_data["title"])

    def clean_description(self):
        return escape(self.cleaned_data["description"])


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True, help_text="A valid email address is required.")

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("This email is already in use.")
        return email

    def clean_text(self):
        return escape(self.cleaned_data["text"])