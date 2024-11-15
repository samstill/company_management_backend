from django.core.management.base import BaseCommand
from accounts.services.erpnext_client import ERPNextClient
import json

class Command(BaseCommand):
    help = 'Test ERPNext authenticated endpoints'

    def handle(self, *args, **options):
        client = ERPNextClient()
        
        # Test basic connectivity
        self.stdout.write('Testing basic connectivity...')
        try:
            response = client.make_request('GET', 'frappe.ping')
            self.stdout.write(self.style.SUCCESS(f'Ping successful: {json.dumps(response)}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Ping failed: {str(e)}'))
            return

        # Test authenticated endpoint
        self.stdout.write('\nTesting authenticated endpoint...')
        try:
            response = client.make_request(
                'GET', 
                'frappe.desk.page.permission_manager.permission_manager.get_roles'
            )
            self.stdout.write(self.style.SUCCESS(
                f'Roles fetched successfully: {json.dumps(response, indent=2)}'
            ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Failed to fetch roles: {str(e)}'))

        # Test user info
        self.stdout.write('\nTesting user info...')
        try:
            response = client.make_request('GET', 'frappe.auth.get_logged_user')
            self.stdout.write(self.style.SUCCESS(
                f'User info: {json.dumps(response, indent=2)}'
            ))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Failed to get user info: {str(e)}')) 