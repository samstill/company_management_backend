from django.conf import settings

ERPNEXT_SETTINGS = {
    'site_url': settings.ERPNEXT_SITE_URL,
    'api_key': settings.ERPNEXT_API_KEY,
    'api_secret': settings.ERPNEXT_API_SECRET,
}

DOCTYPE_PERMISSIONS = {
    'Sales Invoice': ['read', 'write', 'create', 'delete', 'submit', 'cancel'],
    'Sales Order': ['read', 'write', 'create', 'delete', 'submit', 'cancel'],
    'Customer': ['read', 'write', 'create'],
    # Add more doctypes and their permissions as needed
} 