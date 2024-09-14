
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser
from django.utils.translation import gettext_lazy as _

# Define the CustomUserAdmin class
class CustomUserAdmin(UserAdmin):
    # Specify the fields to display in the list view of the admin panel
    list_display = [ 'email', 'first_name', 'last_name', 'role', 'is_staff', 'is_active']
    
    # Specify the fields that can be searched
    search_fields = [ 'email', 'first_name', 'last_name']
    
    # Add filters for user status and role
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'role']
    
    # Customize the fieldsets to include role and other custom fields
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('first_name', 'last_name')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Role'), {'fields': ('role',)}),  # Custom role field
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    # Add the 'role' field to the add form and change form
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role'),
        }),
    )

    # Specify ordering of the displayed users
    ordering = ['email']

# Register the CustomUser model with the CustomUserAdmin
admin.site.register(CustomUser, CustomUserAdmin)
