import requests
import json
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

class ERPNextClient:
    def __init__(self):
        # Use HTTP and port 80 since that's what's working
        self.base_url = 'http://165.22.220.125'
        self.api_key = settings.ERPNEXT_API_KEY
        self.api_secret = settings.ERPNEXT_API_SECRET
        self.headers = {
            'Authorization': f'token {self.api_key}:{self.api_secret}',
            'Content-Type': 'application/json',
        }
        self.timeout = 10

    def make_request(self, method, endpoint, params=None, data=None):
        url = f"{self.base_url}/api/method/{endpoint}"
        logger.info(f"Making request to: {url}")
        
        try:
            if method.lower() == 'get':
                if params and 'filters' in params:
                    params['filters'] = json.dumps(params['filters'])
                response = requests.get(
                    url, 
                    headers=self.headers, 
                    params=params,
                    timeout=self.timeout
                )
            else:
                response = requests.request(
                    method,
                    url,
                    headers=self.headers,
                    json=data,
                    timeout=self.timeout
                )
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"Response Status: {e.response.status_code}")
                logger.error(f"Response Content: {e.response.text}")
            raise

    def test_connection(self):
        """Test basic connectivity to ERPNext"""
        try:
            # Try ping endpoint
            response = self.make_request('GET', 'frappe.ping')
            if response.get('message') == 'pong':
                return True
                
            # Fallback to version endpoint
            response = self.make_request('GET', 'frappe.utils.version.get_versions')
            return bool(response.get('message'))
            
        except Exception as e:
            logger.error(f"Connection test failed: {str(e)}")
            return False

    def verify_credentials(self):
        """Verify API credentials"""
        try:
            response = self.make_request('GET', 'frappe.auth.get_logged_user')
            return bool(response.get('message'))
        except Exception as e:
            logger.error(f"Credential verification failed: {str(e)}")
            return False

    def create_customer(self, user_data):
        """Create a new customer in ERPNext"""
        try:
            customer_data = {
                "doctype": "Customer",
                "customer_name": f"{user_data['first_name']} {user_data['last_name']}",
                "customer_type": "Individual",
                "customer_group": "Individual",
                "territory": "All Territories",  # Or your default territory
                "email_id": user_data['email'],
                "mobile_no": user_data.get('phone', ''),
                "flags": {"ignore_mandatory": True}
            }

            response = self.make_request(
                'POST',
                'frappe.client.insert',
                data=customer_data
            )
            
            return response.get('message')
        except Exception as e:
            logger.error(f"Failed to create customer in ERPNext: {str(e)}")
            raise

    def create_user(self, user_data):
        """Create a new user in ERPNext"""
        try:
            erpnext_user_data = {
                "doctype": "User",
                "email": user_data['email'],
                "first_name": user_data['first_name'],
                "last_name": user_data['last_name'],
                "send_welcome_email": 0,  # Disable welcome email
                "roles": [{"role": role} for role in user_data.get('roles', ['Customer'])],
                "enabled": 1,
            }

            response = self.make_request(
                'POST',
                'frappe.client.insert',
                data=erpnext_user_data
            )
            return response.get('message')
        except Exception as e:
            logger.error(f"Failed to create user in ERPNext: {str(e)}")
            raise