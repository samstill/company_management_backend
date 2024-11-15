from .services import FrappeService
import logging

logger = logging.getLogger(__name__)

def sync_user_to_erpnext(user_id):
    """Sync user data to ERPNext."""
    from .models import CustomUser  # Local import to avoid circular import
    user = CustomUser.objects.get(id=user_id)
    frappe_service = FrappeService()
    try:
        if not user.erpnext_user_id:
            frappe_service.create_user(user)
            user.erpnext_user_id = user.email  # Assuming email is used as user ID
        else:
            frappe_service.update_user(user)
        user.erpnext_sync_status = 'synced'
    except Exception as e:
        logger.error(f"Failed to sync user {user.email} with ERPNext: {str(e)}")
        user.erpnext_sync_status = 'failed'
        user.erpnext_sync_error = str(e)
    finally:
        user.save()  # Save the sync status
