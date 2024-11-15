from django.db import transaction
from ..models import Role, RolePermission

class ERPNextSyncService:
    def sync_roles(self):
        """
        Synchronize roles (simplified version for testing)
        """
        try:
            # Create basic roles
            roles = ['Administrator', 'System Manager', 'User']
            for role_name in roles:
                role, created = Role.objects.get_or_create(
                    name=role_name,
                    defaults={
                        'desk_access': True,
                        'is_custom': False,
                        'disabled': False
                    }
                )
                
                # Create basic permissions
                if created:
                    RolePermission.objects.create(
                        role=role,
                        doctype='User',
                        permission_type='read',
                        value=1
                    )
            return True
        except Exception as e:
            print(f"Error syncing roles: {str(e)}")
            return False