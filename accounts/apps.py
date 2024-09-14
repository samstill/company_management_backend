from django.apps import AppConfig
from django.db.models.signals import post_migrate

class AccountsConfig(AppConfig):
    name = 'accounts'

    def ready(self):
        post_migrate.connect(create_user_roles_and_permissions, sender=self)

def create_user_roles_and_permissions(sender, **kwargs):
    from django.contrib.auth.models import Group, Permission
    from django.contrib.contenttypes.models import ContentType
    from employee.models import Employee
    from company.models import Company

    # Create Manager Group
    manager_group, created = Group.objects.get_or_create(name='Manager')
    if created:
        manager_permissions = Permission.objects.filter(
            content_type__model__in=['employee', 'department']
        )
        manager_group.permissions.set(manager_permissions)

    # Create Executive Director Group
    exec_dir_group, created = Group.objects.get_or_create(name='Executive Director')
    if created:
        exec_dir_permissions = Permission.objects.filter(
            content_type__model__in=['employee', 'department', 'company']
        ).exclude(codename__contains='delete_user')
        exec_dir_group.permissions.set(exec_dir_permissions)

    # Customer Group does not have any specific permissions
    Group.objects.get_or_create(name='Customer')
