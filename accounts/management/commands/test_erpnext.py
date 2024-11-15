from django.core.management.base import BaseCommand
from accounts.services.erpnext_client import ERPNextClient
from django.conf import settings

class Command(BaseCommand):
    help = 'Test ERPNext connection and configuration'

    def handle(self, *args, **options):
        self.stdout.write('Testing ERPNext configuration...')
        self.stdout.write(f'ERPNext URL: {settings.ERPNEXT_SITE_URL}')
        self.stdout.write(f'API Key configured: {"Yes" if settings.ERPNEXT_API_KEY else "No"}')
        self.stdout.write(f'API Secret configured: {"Yes" if settings.ERPNEXT_API_SECRET else "No"}')
        
        client = ERPNextClient()
        
        self.stdout.write('\nTesting ERPNext connectivity...')
        if client.test_connection():
            self.stdout.write(self.style.SUCCESS('Successfully connected to ERPNext'))
        else:
            self.stdout.write(self.style.ERROR('Failed to connect to ERPNext'))
            return
        
        self.stdout.write('\nTesting role fetching...')
        roles = client.get_roles()
        if roles:
            self.stdout.write(self.style.SUCCESS(f'Successfully fetched {len(roles)} roles:'))
            for role in roles:
                self.stdout.write(f"- {role.get('name', 'Unknown')}")
        else:
            self.stdout.write(self.style.ERROR('Failed to fetch roles')) 