from django.contrib import admin
from django.urls import path, include
from accounts.views import home
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),  # <-- Add this
    path('', home, name='home'),
]
if settings.DEBUG:
    urlpatterns += static(settings.EVIDENCE_URL, document_root=settings.EVIDENCE_ROOT)
