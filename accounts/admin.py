from django.contrib import admin
from django.contrib.auth.admin import UserAdmin  # Make sure this import is here
from .models import CustomUser, UserDevice
from django.utils.translation import gettext_lazy as _
from django.contrib.admin import AdminSite
# Define the UserDeviceInline class to show devices in the CustomUser admin page
class UserDeviceInline(admin.TabularInline):
    model = UserDevice
    fields = ['device_name', 'device_type', 'browser', 'operating_system', 'ip_address', 'login_time', 'last_active']
    readonly_fields = ['login_time', 'last_active']
    extra = 0

# Extend the CustomUserAdmin class to include UserDeviceInline
class CustomUserAdmin(UserAdmin):
    list_display = ['email', 'phone_number' ,'first_name', 'last_name', 'role', 'is_staff', 'is_active']
    search_fields = ['email', 'first_name', 'last_name']
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'role']
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal info'), {'fields': ('profile_photo', 'first_name', 'last_name', 'phone_number')}),
        (_('Permissions'), {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions')}),
        (_('Role'), {'fields': ('role',)}),
        (_('Important dates'), {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2', 'role'),
        }),
    )
    
    ordering = ['email']
    
    inlines = [UserDeviceInline]


# Register the CustomUser model with the updated CustomUserAdmin
admin.site.register(CustomUser, CustomUserAdmin)

# Register the UserDevice model to manage devices separately if needed
@admin.register(UserDevice)
class UserDeviceAdmin(admin.ModelAdmin):
    list_display = ['user', 'device_name', 'device_type', 'browser', 'operating_system', 'ip_address', 'login_time', 'last_active']
    search_fields = ['user__email', 'device_name', 'browser', 'ip_address']
    readonly_fields = ['login_time', 'last_active']
    list_filter = ['device_type', 'browser', 'operating_system']
