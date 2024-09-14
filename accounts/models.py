# accounts/models.py

from django.utils import timezone 
from django.contrib.auth.models import AbstractUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.core.mail import send_mail


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
    email = models.EmailField(_('email address'), unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'  # Set email as the unique identifier
    REQUIRED_FIELDS = []  # No other required fields apart from email

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    
    def email_user(self, subject, message, from_email=None, **kwargs):
        """
        Sends an email to this user.
        """
        send_mail(subject, message, from_email, [self.email], **kwargs)


 #     # Choices for the role field   

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



# Example of other models that may relate to Company without causing circular imports
class Project(models.Model):
    name = models.CharField(max_length=100)
    company = models.ForeignKey('company.Company', on_delete=models.CASCADE, related_name='projects')
    manager = models.ForeignKey('employee.Employee', on_delete=models.SET_NULL, null=True, blank=True, related_name='managed_projects')
    description = models.TextField(blank=True, null=True)
    start_date = models.DateField()
    end_date = models.DateField(blank=True, null=True)

    def __str__(self):
        return f'{self.name} in {self.company.name}'
