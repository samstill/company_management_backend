from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth import get_user_model
from .models import CustomUser, UserDevice, Role
from .services.erpnext_client import ERPNextClient
import logging

logger = logging.getLogger(__name__)

User = get_user_model()

@receiver(pre_save, sender=User)
def sync_user_role(sender, instance, **kwargs):
    """Sync role changes to ERPNext"""
    try:
        # Get the old instance if it exists
        if instance.pk:
            old_instance = User.objects.get(pk=instance.pk)
            old_role = old_instance.role
        else:
            old_role = None

        # If role has changed and user exists in ERPNext
        if instance.erpnext_user_id and instance.role != old_role:
            client = ERPNextClient()
            
            # Determine ERPNext roles based on Django role
            erpnext_roles = []
            
            if instance.is_customer():
                erpnext_roles.append('Customer')
            elif instance.is_employee():
                erpnext_roles.append('Employee')
            elif instance.is_manager():
                erpnext_roles.extend(['Employee', 'Manager'])
            elif instance.is_executive_director():
                erpnext_roles.extend(['Employee', 'Manager', 'System Manager'])
            elif instance.is_admin():
                erpnext_roles.extend(['Administrator', 'System Manager'])

            # Update roles in ERPNext
            client.make_request(
                'POST',
                'frappe.client.set_value',
                data={
                    'doctype': 'User',
                    'name': instance.erpnext_user_id,
                    'fieldname': 'roles',
                    'value': [{'role': role} for role in erpnext_roles]
                }
            )
            
            instance.erpnext_sync_status = 'synced'
            
    except Exception as e:
        logger.error(f"Failed to sync role to ERPNext: {str(e)}")
        instance.erpnext_sync_status = 'failed'
        instance.erpnext_sync_error = str(e)

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Handle post-save actions for User model"""
    if created:
        try:
            # Create user in ERPNext if not already done
            if not instance.erpnext_user_id:
                instance._create_erpnext_user()
        except Exception as e:
            logger.error(f"Failed to create user in ERPNext: {str(e)}")

@receiver(post_save, sender=Role)
def sync_role_to_erpnext(sender, instance, created, **kwargs):
    """Sync new roles to ERPNext"""
    if created:
        try:
            client = ERPNextClient()
            client.make_request(
                'POST',
                'frappe.client.insert',
                data={
                    'doctype': 'Role',
                    'role_name': instance.name,
                    'desk_access': instance.desk_access,
                    'disabled': instance.disabled
                }
            )
        except Exception as e:
            logger.error(f"Failed to sync role to ERPNext: {str(e)}")

@receiver(post_save, sender=UserDevice)
def handle_user_device(sender, instance, created, **kwargs):
    """Handle post-save actions for UserDevice model"""
    if created:
        logger.info(f"New device registered for user {instance.user.email}: {instance.device_name or instance.browser}")