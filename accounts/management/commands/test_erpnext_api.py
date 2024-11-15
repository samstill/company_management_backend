from django.core.management.base import BaseCommand
from accounts.services.erpnext_client import ERPNextClient
import json

class Command(BaseCommand):
    help = 'Test ERPNext API functionality'

    def handle(self, *args, **options):
        client = ERPNextClient()
        
        # Test basic connection
        self.stdout.write('Testing connection...')
        if client.test_connection():
            self.stdout.write(self.style.SUCCESS('Connection successful'))
        else:
            self.stdout.write(self.style.ERROR('Connection failed'))
            return

        # Test roles endpoint
        self.stdout.write('\nFetching roles...')
        try:
            roles = client.get_roles()
            self.stdout.write(self.style.SUCCESS(
                f'Roles fetched successfully:\n{json.dumps(roles, indent=2)}'
            ))
            
            # If roles were fetched, test permissions for first role
            if roles:
                role_name = roles[0].get('name')
                self.stdout.write(f'\nFetching permissions for role: {role_name}')
                permissions = client.get_role_permissions(role_name)
                self.stdout.write(self.style.SUCCESS(
                    f'Permissions fetched successfully:\n{json.dumps(permissions, indent=2)}'
                ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error: {str(e)}'))