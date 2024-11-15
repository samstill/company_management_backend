from django.core.exceptions import ValidationError
from django.conf import settings
import requests
import logging

logger = logging.getLogger(__name__)

class ERPNextService:
    def __init__(self):
        self.session = self._create_session()

    def _create_session(self):
        """Create a requests session with retry strategy."""
        session = requests.Session()
        retry_strategy = requests.adapters.Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["POST", "GET"]
        )
        adapter = requests.adapters.HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _make_request(self, url: str, data: dict):
        """Make a request to the Frappe API with error handling."""
        try:
            response = self.session.post(url, json=data, headers=self._get_headers(), timeout=(30, 30))
            response.raise_for_status()  # Raise an error for bad responses
            return response
        except requests.Timeout:
            raise ValidationError("Connection to Frappe server timed out. Please try again.")
        except requests.ConnectionError as e:
            raise ValidationError(f"Could not connect to Frappe server. Error: {str(e)}")
        except requests.HTTPError as e:
            logger.error(f"HTTPError: {str(e)} - Response: {response.text}")  # Log the response content
            if response.status_code == 500:
                logger.error("Max retries exceeded for URL: %s", url)
                raise ValidationError("Server error occurred. Please check the server logs.")
            raise ValidationError(f"Error during API call: {str(e)} - Response: {response.text}")
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")  # Log unexpected errors
            raise ValidationError(f"Error during API call: {str(e)}")

    def _get_headers(self) -> dict:
        """Get headers for Frappe API requests."""
        return {
            'Authorization': f'token {settings.FRAPPE_API_KEY}:{settings.FRAPPE_API_SECRET}',
            'Content-Type': 'application/json'
        }

    def get_user(self, user_id):
        url = f"{self.base_url}/api/resource/User/{user_id}"
        response = requests.get(url, headers=self._get_headers())
        response.raise_for_status()
        return response.json()

    def create_user(self, user_data):
        """Create a new user in Frappe."""
        # Check if the user already exists
        check_url = f'{settings.FRAPPE_BASE_URL}/api/method/frappe.client.get_value'
        check_data = {
            "doctype": "User",
            "filters": {"email": user_data['email']},
            "fieldname": ["name"]
        }
        response = self._make_request(check_url, check_data)

        if response.ok and response.json().get('message'):
            raise ValidationError("User with this email already exists.")

        # Proceed to create the user
        data = {
            "doctype": "User",
            "email": user_data['email'],
            "first_name": user_data.get('first_name', ""),
            "last_name": user_data.get('last_name', ""),
            "enabled": 1 if user_data.get('is_active', True) else 0,
            # Add any other required fields here
        }
        logger.debug(f"Creating user with data: {data}")
        url = f'{settings.FRAPPE_BASE_URL}/api/method/frappe.client.insert'
        self._make_request(url, data)

    def update_user(self, user_data):
        """Update existing user in Frappe or create if not exists."""
        # Check if the user exists first
        check_url = f'{settings.FRAPPE_BASE_URL}/api/method/frappe.client.get_value'
        check_data = {
            "doctype": "User",
            "filters": {"email": user_data['email']},
            "fieldname": ["name"]
        }
        response = self._make_request(check_url, check_data)

        if response.ok and response.json().get('message'):
            # User exists, update the user
            data = {
                "doctype": "User",
                "name": response.json()['message'],  # Use the name from the response
                "first_name": user_data.get('first_name', ""),
                "last_name": user_data.get('last_name', ""),
                "enabled": 1 if user_data.get('is_active', True) else 0
            }
            url = f'{settings.FRAPPE_BASE_URL}/api/method/frappe.client.set_value'
            self._make_request(url, data)
        else:
            # User does not exist, create the user
            self.create_user(user_data)

    def delete_user(self, user_id):
        url = f"{self.base_url}/api/resource/User/{user_id}"
        response = requests.delete(url, headers=self._get_headers())
        return response.json()
