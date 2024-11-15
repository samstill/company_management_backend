import requests
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class FrappeService:
    """Service class to handle Frappe API interactions."""

    def __init__(self):
        self.session = self._create_session()

    def _create_session(self):
        """Create a requests session with retry strategy."""
        session = requests.Session()
        return session

    # Add other methods for creating and updating users
