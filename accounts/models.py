from django.utils import timezone 
from django.contrib.auth.models import Group, Permission
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _
from django.core.mail import send_mail
from django.conf import settings
from django.core.validators import FileExtensionValidator


class CustomUserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        """
        Create and return a user with an email and password.
        """
        if not email:
            raise ValueError(_("The Email field must be set"))
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and return a superuser with an email and password.
        """
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
    validators=[FileExtensionValidator(allowed_extensions=['jpg', 'jpeg', 'png'])],
    help_text=_("profile photo.")
    )

    USERNAME_FIELD = 'email'  # Set email as the unique identifier
    REQUIRED_FIELDS = []  # No other required fields apart from email

    objects = CustomUserManager()

    # Choices for the role field   
    ADMIN = 'admin'
    MANAGER = 'manager'
    EXECUTIVE_DIRECTOR = 'executive_director'
    EMPLOYEE = 'employee'
    CUSTOMER = 'customer'

    ROLE_CHOICES = [
        (ADMIN, 'Admin'),
        (MANAGER, 'Manager'),
        (EXECUTIVE_DIRECTOR, 'Executive Director'),
        (EMPLOYEE, 'Employee'),
        (CUSTOMER, 'Customer'),
    ]

    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default=CUSTOMER)
    
    def is_manager(self):
        return self.role == self.MANAGER

    def is_executive_director(self):
        return self.role == self.EXECUTIVE_DIRECTOR
    
    def is_employee(self):
        return self.role == self.EMPLOYEE

    def is_admin(self):
        return self.role == self.ADMIN

    def is_customer(self):
        return self.role == self.CUSTOMER

    def __str__(self):
        return self.email

    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this user.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)

    def save(self, *args, **kwargs):
        # Track if this is a new instance or an update
        is_new_instance = self._state.adding

        # Store the original role before saving
        original_role = None
        if not is_new_instance:
            original_role = CustomUser.objects.get(pk=self.pk).role

        # Call the original save method to ensure the user is saved to the database
        super(CustomUser, self).save(*args, **kwargs)

        # Check if the role has changed or if this is a new user
        if is_new_instance or (original_role != self.role):
            # Clear existing groups to avoid conflicting group memberships
            self.groups.clear()

            # Determine the group based on the user's role
            group_name = None
            if self.role == self.MANAGER:
                group_name = 'Manager'
            elif self.role == self.EXECUTIVE_DIRECTOR:
                group_name = 'Executive Director'
            elif self.role == self.EMPLOYEE:
                group_name = 'Employee'
            elif self.role == self.CUSTOMER:
                group_name = 'Customer'

            # If group_name is determined, proceed to add the user to the correct group
            if group_name:
                # Get or create the group
                group, created = Group.objects.get_or_create(name=group_name)

                # Assign default permissions to the group if it's newly created
                if created:
                    self.assign_permissions_to_group(group, group_name)

                # Add the user to the specific group
                self.groups.add(group)

    def assign_permissions_to_group(self, group, group_name):
        """
        Helper method to assign default permissions to a group.
        Adjust as necessary for your use case.
        """
        # Define default permissions based on the group name
        permissions = []
        if group_name == 'Manager':
            permissions = ['view_employee', 'change_employee', 'delete_employee']
        elif group_name == 'Executive Director':
            permissions = ['view_employee']
        elif group_name == 'Employee':
            permissions = ['view_employee']
        elif group_name == 'Customer':
            permissions = []

        # Assign the permissions to the group
        content_type = ContentType.objects.get(app_label='employee', model='employee')
        for perm in permissions:
            permission = Permission.objects.filter(codename=perm, content_type=content_type).first()
            if permission:
                group.permissions.add(permission)

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