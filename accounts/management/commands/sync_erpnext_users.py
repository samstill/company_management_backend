from django.core.management.base import BaseCommand
from django.db import transaction
from accounts.models import CustomUser, Role
from accounts.services.erpnext_client import ERPNextClient
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sync users between ERPNext and Django'

    def add_arguments(self, parser):
        parser.add_argument(
            '--direction',
            choices=['both', 'to-django', 'to-erpnext'],
            default='both',
            help='Sync direction'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be done without making changes'
        )

    def handle(self, *args, **options):
        client = ERPNextClient()
        direction = options['direction']
        dry_run = options['dry_run']

        if direction in ['both', 'to-django']:
            self.sync_from_erpnext(client, dry_run)
        
        if direction in ['both', 'to-erpnext']:
            self.sync_to_erpnext(client, dry_run)

    def sync_from_erpnext(self, client, dry_run):
        """Sync users from ERPNext to Django"""
        try:
            # Get all users from ERPNext
            erpnext_users = client.make_request(
                'GET',
                'frappe.client.get_list',
                params={
                    'doctype': 'User',
                    'fields': ['name', 'email', 'first_name', 'last_name', 'enabled', 'roles']
                }
            )

            for erp_user in erpnext_users.get('message', []):
                try:
                    with transaction.atomic():
                        # Skip system users and disabled users
                        if not erp_user.get('email') or not erp_user.get('enabled'):
                            continue

                        # Determine role based on ERPNext roles
                        role_name = self.determine_django_role(erp_user.get('roles', []))
                        role = Role.objects.get(name=role_name) if role_name else None

                        # Try to find existing user
                        user, created = CustomUser.objects.get_or_create(
                            email=erp_user['email'],
                            defaults={
                                'first_name': erp_user.get('first_name', ''),
                                'last_name': erp_user.get('last_name', ''),
                                'is_active': erp_user.get('enabled', True),
                                'erpnext_user_id': erp_user.get('name'),
                                'erpnext_sync_status': 'synced',
                                'role': role
                            }
                        )

                        if not created:
                            if not dry_run:
                                # Update existing user
                                user.first_name = erp_user.get('first_name', '')
                                user.last_name = erp_user.get('last_name', '')
                                user.is_active = erp_user.get('enabled', True)
                                user.erpnext_user_id = erp_user.get('name')
                                user.erpnext_sync_status = 'synced'
                                user.role = role
                                user.save()

                        action = 'Would create' if dry_run else 'Created' if created else 'Updated'
                        self.stdout.write(
                            self.style.SUCCESS(
                                f"{action} user {erp_user['email']} with role {role_name}"
                            )
                        )

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Error processing user {erp_user.get('email')}: {str(e)}"
                        )
                    )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Failed to fetch ERPNext users: {str(e)}")
            )

    def sync_to_erpnext(self, client, dry_run):
        """Sync users from Django to ERPNext"""
        try:
            # Get all Django users that need syncing
            django_users = CustomUser.objects.filter(
                is_active=True,
                erpnext_sync_status__in=['pending', 'failed']
            )

            for user in django_users:
                try:
                    if not dry_run:
                        user._create_erpnext_user()
                    
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"{'Would sync' if dry_run else 'Synced'} user {user.email} to ERPNext"
                        )
                    )

                except Exception as e:
                    self.stdout.write(
                        self.style.ERROR(
                            f"Error syncing user {user.email}: {str(e)}"
                        )
                    )

        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f"Failed to sync users to ERPNext: {str(e)}")
            )

    def determine_django_role(self, erpnext_roles):
        """Map ERPNext roles to Django roles"""
        role_mapping = {
            'Administrator': 'Admin',
            'System Manager': 'Manager',
            'Employee': 'Employee',
            'Customer': 'Customer'
        }

        # Convert role objects to role names
        role_names = [r.get('role') for r in erpnext_roles if isinstance(r, dict)]

        # Check roles in priority order
        if 'Administrator' in role_names:
            return 'Admin'
        elif 'System Manager' in role_names:
            return 'Manager'
        elif 'Employee' in role_names:
            return 'Employee'
        elif 'Customer' in role_names:
            return 'Customer'
        
        return None 