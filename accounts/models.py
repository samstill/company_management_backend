import logging
from django.utils import timezone
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.mail import send_mail
from django.conf import settings
from .services.erpnext_service import ERPNextService
from .services.erpnext_client import ERPNextClient
from django.core.exceptions import ValidationError
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from .tasks import sync_user_to_erpnext_task  # Import the task

# Constants for Frappe API URLs
FRAPPE_BASE_URL = settings.FRAPPE_BASE_URL
FRAPPE_API_KEY = settings.FRAPPE_API_KEY
FRAPPE_API_SECRET = settings.FRAPPE_API_SECRET

logger = logging.getLogger(__name__)

class CustomUserManager(BaseUserManager):
    def create_user(self, email: str, password: str = None, **extra_fields) -> 'CustomUser':
        """Create and return a user with an email and password."""
        if not email:
            raise ValueError(_("The Email field must be set"))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        
        # Sync with ERPNext asynchronously
        sync_user_to_erpnext_task.delay(user.id)
        
        return user

    def create_superuser(self, email: str, password: str = None, **extra_fields) -> 'CustomUser':
        """Create and return a superuser with an email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))

        return self.create_user(email, password=password, **extra_fields)

class CustomUser(AbstractUser, PermissionsMixin):
    username = None  # Remove the username field
    email = models.EmailField(_('email address'), unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    profile_photo = models.ImageField(
        upload_to='profile_photos/',
        null=True,
        blank=True,
        help_text=_("Profile photo.")
    )
    erpnext_customer_id = models.CharField(max_length=140, blank=True, null=True)
    erpnext_user_id = models.CharField(max_length=140, blank=True, null=True, help_text=_("User ID in ERPNext system"))
    erpnext_sync_status = models.CharField(max_length=20, choices=[('pending', 'Pending'), ('synced', 'Synced'), ('failed', 'Failed')], default='pending')
    erpnext_sync_error = models.TextField(blank=True, null=True)

    USERNAME_FIELD = 'email'  # Set email as the unique identifier
    REQUIRED_FIELDS = []  # No other required fields apart from email

    objects = CustomUserManager()

    # Role choices
    ROLE_CHOICES = [
        ('Admin', 'Admin'),
        ('Manager', 'Manager'),
        ('Executive Director', 'Executive Director'),
        ('Employee', 'Employee'),
        ('Customer', 'Customer'),
    ]
    role = models.ForeignKey('Role', on_delete=models.SET_NULL, null=True, blank=True, related_name='users', verbose_name=_('Role'))

    def save(self, *args, **kwargs):
        """Override save method to handle user updates and sync with ERPNext."""
        super().save(*args, **kwargs)
        erp_service = ERPNextService()
        user_data = self._prepare_user_data()
        
        if self.pk:  # If the user already exists, update
            erp_service.update_user(user_data)  # Pass user_data here
        else:  # If it's a new user, create
            erp_service.create_user(user_data)

    def _prepare_user_data(self) -> dict:
        """Prepare user data for ERPNext."""
        return {
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "is_active": self.is_active,  # Include is_active if needed
            # Add other fields as necessary
        }

    def delete(self, *args, **kwargs):
        """Override delete method to remove user from ERPNext."""
        erp_service = ERPNextService()
        erp_service.delete_user(self.pk)
        super().delete(*args, **kwargs)

    def __str__(self) -> str:
        return self.email

    def email_user(self, subject: str, message: str, from_email: str = None, **kwargs):
        """Sends an email to this user."""
        send_mail(subject, message, from_email, [self.email], **kwargs)

class FrappeService:
    """Service class to handle Frappe API interactions."""

    def __init__(self):
        self.session = self._create_session()

    def _create_session(self):
        """Create a requests session with retry strategy."""
        session = requests.Session()
        retry_strategy = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504], allowed_methods=["POST", "GET"])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def create_user(self, user: CustomUser):
        """Create a new user in Frappe."""
        data = {
            "doc": {
                "doctype": "User",
                "email": user.email,
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "send_welcome_email": 0,
                "enabled": 1 if user.is_active else 0,
                "user_type": "System User",
                "roles": [
                    {"role": "Employee", "parentfield": "roles", "parenttype": "User"},
                    {"role": "Blogger", "parentfield": "roles", "parenttype": "User"}
                ]
            }
        }
        url = f'{FRAPPE_BASE_URL}/api/method/frappe.client.insert'
        self._make_request(url, data)

    def update_user(self, user: CustomUser):
        """Update existing user in Frappe."""
        data = {
            "doctype": "User",
            "name": user.email,
            "fieldname": {
                "first_name": user.first_name or "",
                "last_name": user.last_name or "",
                "enabled": 1 if user.is_active else 0
            }
        }
        url = f'{FRAPPE_BASE_URL}/api/method/frappe.client.set_value'
        self._make_request(url, data)

    def delete_user(self, user_id: str):
        """Delete user from Frappe."""
        data = {
            "doctype": "User",
            "name": user_id
        }
        url = f'{FRAPPE_BASE_URL}/api/method/frappe.client.delete'
        self._make_request(url, data)

    def _make_request(self, url: str, data: dict):
        """Make a request to the Frappe API with error handling."""
        try:
            response = self.session.post(url, json=data, headers=self._get_headers(), timeout=(30, 30))
            response.raise_for_status()  # Raise an error for bad responses
            return response
        except requests.Timeout:
            raise ValidationError("Connection to Frappe server timed out. Please try again.")
        except requests.ConnectionError as e:
            raise ValidationError(f"Could not connect to Frappe server. Error: {str(e)}")
        except Exception as e:
            raise ValidationError(f"Error during API call: {str(e)}")

    def _get_headers(self) -> dict:
        """Get headers for Frappe API requests."""
        return {
            'Authorization': f'token {FRAPPE_API_KEY}:{FRAPPE_API_SECRET}',
            'Content-Type': 'application/json'
        }

    def check_user_exists(self, email: str) -> bool:
        """Check if the user exists in Frappe."""
        check_url = f'{FRAPPE_BASE_URL}/api/method/frappe.client.get_value'
        check_data = {
            "doctype": "User",
            "filters": {"email": email},
            "fieldname": ["name"]
        }
        response = self._make_request(check_url, check_data)
        return response.ok and response.json().get('message')

class UserDevice(models.Model):
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    device_name = models.CharField(max_length=255, blank=True, null=True)
    device_type = models.CharField(max_length=50, blank=True, null=True)
    browser = models.CharField(max_length=100)
    operating_system = models.CharField(max_length=100)
    ip_address = models.GenericIPAddressField(null=True)
    login_time = models.DateTimeField(default=timezone.now)
    last_active = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.device_name or self.browser} ({self.ip_address})"

class Role(models.Model):
    name = models.CharField(
        max_length=100, 
        unique=True,
        help_text=_("Role name")
    )
    desk_access = models.BooleanField(default=True, help_text=_("Allow desk access"))
    is_custom = models.BooleanField(default=True, help_text=_("Is this a custom role"))
    disabled = models.BooleanField(default=False)
    desk_shortcuts = models.JSONField(default=dict, blank=True)
    permissions = models.JSONField(default=dict, blank=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        
    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        is_new = self._state.adding
        super().save(*args, **kwargs)
        
        if is_new:
            try:
                # Sync new role to ERPNext
                client = ERPNextClient()
                client.make_request(
                    'POST',
                    'frappe.client.insert',
                    data={
                        'doctype': 'Role',
                        'role_name': self.name,
                        'desk_access': self.desk_access,
                        'disabled': self.disabled
                    }
                )
            except Exception as e:
                logger.error(f"Failed to sync role to ERPNext: {str(e)}")

class RolePermission(models.Model):
    PERMISSION_TYPES = [
        ('create', 'Create'),
        ('read', 'Read'),
        ('write', 'Write'),
        ('delete', 'Delete'),
        ('submit', 'Submit'),
        ('cancel', 'Cancel'),
        ('amend', 'Amend'),
        ('report', 'Report'),
    ]

    role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='role_permissions')
    doctype = models.CharField(max_length=255, help_text=_("Document Type"))
    permission_type = models.CharField(max_length=20, choices=PERMISSION_TYPES)
    value = models.IntegerField(default=0, help_text=_("Permission Level (0 or 1)"))

    class Meta:
        unique_together = ('role', 'doctype', 'permission_type')

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        try:
            # Sync permission to ERPNext
            client = ERPNextClient()
            client.make_request(
                'POST',
                'frappe.client.insert',
                data={
                    'doctype': 'Custom DocPerm',
                    'role': self.role.name,
                    'parent': self.doctype,
                    'permlevel': 0,
                    self.permission_type.lower(): self.value
                }
            )
        except Exception as e:
            logger.error(f"Failed to sync permission to ERPNext: {str(e)}")
