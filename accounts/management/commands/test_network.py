from django.core.management.base import BaseCommand
import socket
import subprocess
import requests
import time

class Command(BaseCommand):
    help = 'Test network connectivity to ERPNext server'

    def handle(self, *args, **options):
        host = '165.22.220.125'
        self.stdout.write(f'\nTesting connectivity to {host}...\n')

        # 1. DNS Resolution
        try:
            ip = socket.gethostbyname(host)
            self.stdout.write(self.style.SUCCESS(f'DNS Resolution: {host} -> {ip}'))
        except socket.gaierror as e:
            self.stdout.write(self.style.ERROR(f'DNS Resolution failed: {str(e)}'))

        # 2. Socket Connection Test
        common_ports = [80, 443, 8000, 8001, 8003]
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((host, port))
                if result == 0:
                    self.stdout.write(self.style.SUCCESS(f'Port {port}: OPEN'))
                else:
                    self.stdout.write(self.style.ERROR(f'Port {port}: CLOSED'))
                sock.close()
            except Exception as e:
                self.stdout.write(self.style.ERROR(f'Port {port}: Error - {str(e)}'))

        # 3. HTTP Request Test
        protocols = ['http', 'https']
        for protocol in protocols:
            for port in common_ports:
                url = f'{protocol}://{host}:{port}/api/method/frappe.ping'
                try:
                    start_time = time.time()
                    response = requests.get(url, timeout=5)
                    elapsed = time.time() - start_time
                    self.stdout.write(self.style.SUCCESS(
                        f'\n{url}\n'
                        f'Response time: {elapsed:.2f}s\n'
                        f'Status code: {response.status_code}\n'
                        f'Content: {response.text[:100]}'
                    ))
                except requests.exceptions.RequestException as e:
                    self.stdout.write(self.style.ERROR(f'{url} - Failed: {str(e)}'))

        # 4. Traceroute (if available)
        try:
            traceroute = subprocess.run(['traceroute', host], 
                                      capture_output=True, 
                                      text=True, 
                                      timeout=30)
            self.stdout.write('\nTraceroute results:')
            self.stdout.write(traceroute.stdout)
        except Exception as e:
            self.stdout.write(self.style.WARNING(
                f'\nTraceroute not available or failed: {str(e)}'
            )) 