from django.core.management.base import BaseCommand
from accounts.services.erpnext_client import ERPNextClient
from django.conf import settings
import socket
import requests
import time

class Command(BaseCommand):
    help = 'Detailed ERPNext connection testing'

    def test_dns(self, host):
        """Test DNS resolution"""
        try:
            ip = socket.gethostbyname(host)
            self.stdout.write(self.style.SUCCESS(f'DNS Resolution: {host} -> {ip}'))
            return True
        except socket.gaierror as e:
            self.stdout.write(self.style.ERROR(f'DNS Resolution failed: {str(e)}'))
            return False

    def test_port(self, host, port):
        """Test if port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            self.stdout.write(self.style.SUCCESS(f'Port {port} is open'))
            return True
        else:
            self.stdout.write(self.style.ERROR(f'Port {port} is closed'))
            return False

    def test_http(self, url):
        """Test basic HTTP connection"""
        try:
            # Test with multiple endpoints
            endpoints = [
                '/api/method/frappe.ping',
                '/api/method/version',
                '/'
            ]
            
            for endpoint in endpoints:
                test_url = f"{url.rstrip('/')}{endpoint}"
                self.stdout.write(f'\nTesting endpoint: {test_url}')
                
                start_time = time.time()
                response = requests.get(
                    test_url, 
                    timeout=(10, 30),  # (connect timeout, read timeout)
                    headers={'Accept': 'application/json'}
                )
                elapsed = time.time() - start_time
                
                self.stdout.write(self.style.SUCCESS(
                    f'Connection successful (took {elapsed:.2f}s)\n'
                    f'Status: {response.status_code}\n'
                    f'Content-Type: {response.headers.get("content-type", "Unknown")}\n'
                    f'Content-Length: {len(response.content)} bytes'
                ))
                
                # If any endpoint responds, consider it a success
                return True
                
        except requests.exceptions.RequestException as e:
            self.stdout.write(self.style.ERROR(f'HTTP Connection failed: {str(e)}'))
            return False

    def handle(self, *args, **options):
        # Get host from settings
        url = settings.ERPNEXT_SITE_URL
        if not url:
            self.stdout.write(self.style.ERROR('ERPNext URL not configured'))
            return
        
        # Parse URL
        if not url.startswith(('http://', 'https://')):
            url = f'http://{url}'
        
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        self.stdout.write(self.style.NOTICE(f'\nTesting connection to {url}'))
        self.stdout.write('-' * 50)
        
        # Test DNS
        self.stdout.write('\n1. Testing DNS resolution...')
        if not self.test_dns(host):
            return
        
        # Test Port
        self.stdout.write('\n2. Testing port connectivity...')
        if not self.test_port(host, port):
            return
        
        # Test HTTP
        self.stdout.write('\n3. Testing HTTP connection...')
        if not self.test_http(url):
            return
        
        # Test ERPNext API
        self.stdout.write('\n4. Testing ERPNext API...')
        client = ERPNextClient()
        
        # Test basic connection
        self.stdout.write('\nTesting basic connection...')
        if client.test_connection():
            self.stdout.write(self.style.SUCCESS('Basic connection successful'))
        else:
            self.stdout.write(self.style.ERROR('Basic connection failed'))
            return
        
        # Test credentials
        self.stdout.write('\nTesting API credentials...')
        if client.verify_credentials():
            self.stdout.write(self.style.SUCCESS('API credentials verified'))
        else:
            self.stdout.write(self.style.ERROR('API credential verification failed')) 