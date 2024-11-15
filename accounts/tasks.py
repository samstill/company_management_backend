from celery import shared_task

@shared_task
def sync_user_to_erpnext_task(user_id):
    from .models import CustomUser
    from .services.erpnext_service import ERPNextService

    erp_service = ERPNextService()
    # Your logic to sync user to ERPNext