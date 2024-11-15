from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, UserDevice, Role, RolePermission

class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'role', 'is_staff', 'erpnext_sync_status')
    list_filter = ('is_staff', 'is_superuser', 'is_active', 'role', 'erpnext_sync_status')
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name', 'profile_photo')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'role')}),
        ('ERPNext Info', {'fields': ('erpnext_user_id', 'erpnext_customer_id', 'erpnext_sync_status', 'erpnext_sync_error')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'last_name', 'password1', 'password2', 'role'),
        }),
    )
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    readonly_fields = ('erpnext_user_id', 'erpnext_customer_id', 'erpnext_sync_status', 'erpnext_sync_error')

    def save_model(self, request, obj, form, change):
        try:
            obj.save()
        except Exception as e:
            self.message_user(request, f"Error syncing with ERPNext: {str(e)}", level='ERROR')
            raise

admin.site.register(CustomUser, CustomUserAdmin)
admin.site.register(UserDevice)
admin.site.register(Role)
admin.site.register(RolePermission)
