from django.core.management.base import BaseCommand
from accounts.services import ERPNextRoleSync

class Command(BaseCommand):
    help = 'Synchronize roles and permissions from ERPNext'

    def handle(self, *args, **options):
        self.stdout.write('Starting ERPNext role synchronization...')
        ERPNextRoleSync.sync_roles()
        self.stdout.write(self.style.SUCCESS('Successfully synchronized roles from ERPNext')) 