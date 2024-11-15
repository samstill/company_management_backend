from django.core.management.base import BaseCommand
import socket
import requests
from urllib.parse import urlparse
import time

class Command(BaseCommand):
    help = 'Test ERPNext connection on multiple ports'

    def test_port(self, host, port):
        """Test if a port is open"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0

    def test_http(self, url, port):
        """Test HTTP connection on a specific port"""
        try:
            test_url = f"{url}:{port}/api/method/frappe.ping"
            response = requests.get(test_url, timeout=5)
            return response.status_code == 200
        except:
            return False

    def handle(self, *args, **options):
        host = "165.22.220.125"
        ports = [80, 443, 8000, 8001, 8003, 3000]  # Common ERPNext ports
        
        self.stdout.write(f'Testing connection to {host} on multiple ports...\n')
        
        for port in ports:
            self.stdout.write(f'\nTesting port {port}:')
            if self.test_port(host, port):
                self.stdout.write(self.style.SUCCESS(f'Port {port} is OPEN'))
                
                # If port is open, try HTTP connection
                if self.test_http(f"http://{host}", port):
                    self.stdout.write(
                        self.style.SUCCESS(f'HTTP connection successful on port {port}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'Port {port} is open but no HTTP response')
                    )
            else:
                self.stdout.write(self.style.ERROR(f'Port {port} is CLOSED')) 