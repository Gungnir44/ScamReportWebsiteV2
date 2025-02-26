# Scam Victim Report Website

## Project Overview
The **Scam Victim Report Website** is a Django-based web application designed to help users report and track scam activities. The project allows users to submit scam reports, comment on existing reports, view flagged scam websites, and donate to support the platform.

## Features
- **User Authentication**
  - Secure registration and login system
  - Two-factor authentication (2FA) (optional)
  - Admin management for user roles

- **Scam Report Submission**
  - Users can submit scam reports with details and evidence (images/PDFs)
  - Automated metadata extraction for uploaded files
  - URL validation and analysis for scam websites
  - Reports are stored securely in a database

- **Viewing Reports and Websites**
  - Public list of user-submitted scam reports
  - Dedicated flagged scam website list
  - User comments on reports
  - Credibility scoring based on user feedback

- **User Verification & Security**
  - IP logging and geolocation tracking
  - WHOIS lookup and metadata validation
  - Integration with external scam databases

- **Admin Dashboard**
  - Manage users and scam reports
  - Approve, flag, or reject reports
  - Ban/unban users

- **Donation System**
  - Accepts user donations via Stripe/PayPal
  - Tracks donations in the database

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/Gungnir44/ScamReportWebsiteV2.git
cd ScamReportWebsiteV2

2. Set Up Virtual Environment
python -m venv .venv
source .venv/bin/activate  # For Linux/Mac
.venv\Scripts\activate  # For Windows

3. Install Dependencies
pip install -r requirements.txt

4. Apply Migrations
python manage.py makemigrations accounts
python manage.py migrate

5. Create Superuser (Admin)
python manage.py createsuperuser

6. Run the Server
python manage.py runserver
Access the website at: http://127.0.0.1:8000/

Directory Structure
ScamReportWebsiteV2/
│── accounts/                 # Django app for user authentication and reports
│   ├── migrations/           # Database migrations
│   ├── static/               # Static files (CSS, JS, images)
│   ├── templates/            # HTML templates
│   ├── views.py              # Handles application logic
│   ├── models.py             # Database models
│   ├── urls.py               # URL routing
│── templates/                 # Main template folder
│── static/                    # Static assets
│── db.sqlite3                  # SQLite database (auto-generated)
│── manage.py                   # Django project management script
│── requirements.txt             # Required dependencies
│── README.txt                   # Project documentation

API & External Integrations
-WHOIS Lookup API (for scam website validation)
-External scam databases (optional)
-Stripe/PayPal (for donations)

Known Issues & Debugging
-Issue: Server not starting?
 Fix: Ensure .venv is activated before running python manage.py runserver.
-Issue: Database migration errors?
 Fix: Try running:
 python manage.py migrate --fake
-Issue: Admin dashboard login redirecting?
 Fix: Ensure you're using a superuser account.

Future Improvements
-Implement email verification for users
-Add an API for external scam report submissions
-Improve UI/UX for mobile compatibility
