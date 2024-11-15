from rest_framework import permissions
from .models import RolePermission

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'admin'

class IsManager(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'manager'

class IsSupervisor(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'supervisor'

class IsViewer(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'viewer'

class ERPNextPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False

        # Get the doctype from the view (you'll need to add this to your views)
        doctype = getattr(view, 'doctype', None)
        if not doctype:
            return False

        # Get the required permission type based on the HTTP method
        method_permission_mapping = {
            'GET': 'read',
            'POST': 'create',
            'PUT': 'write',
            'PATCH': 'write',
            'DELETE': 'delete',
        }
        
        permission_type = method_permission_mapping.get(request.method)
        if not permission_type:
            return False

        # Check if the user's role has the required permission
        return RolePermission.objects.filter(
            role=request.user.role,
            doctype=doctype,
            permission_type=permission_type,
            value=1
        ).exists()

ERPNEXT_SITE = 'your-site-name'
ERPNEXT_HOST = 'your-erpnext-host'
ERPNEXT_API_KEY = 'your-api-key'
ERPNEXT_API_SECRET = 'your-api-secret'
