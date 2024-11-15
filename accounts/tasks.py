from celery import shared_task
from .services.sync_service import ERPNextSyncService

@shared_task
def sync_erpnext_roles():
    sync_service = ERPNextSyncService()
    sync_service.sync_roles() 