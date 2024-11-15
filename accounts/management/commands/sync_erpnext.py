from django.core.management.base import BaseCommand
from accounts.services.sync_service import ERPNextSyncService

class Command(BaseCommand):
    help = 'Synchronize roles and permissions from ERPNext'

    def handle(self, *args, **options):
        sync_service = ERPNextSyncService()
        
        self.stdout.write('Starting ERPNext synchronization...')
        
        try:
            sync_service.sync_roles()
            self.stdout.write(self.style.SUCCESS('Successfully synchronized roles and permissions'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Error during synchronization: {str(e)}')) 