#! /usr/bin/env python3

import socket
import concurrent.futures
from datetime import datetime
import ipaddress

class PortScanner:
    def __init__(self, timeout= timeout, max_threads =  100):
        self.timeout
        self.max_threads = max_threads
        self.open_ports = {}

    def scan_port(self, target, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)

            try:
                result = sock.connect_ex((target, port))

                if result == 0:
                    try:
                        sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    except:
                        banner = 'BANNER UNAVAILABLE'

                    return port, banner

            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

            return None

    def scan_range(self, target, start_port=1, end_port=1024):
        print(f"[*] Scanning {target} | Ports {start_port}-{end_port} |  {datetime.now()} ")
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, target, port): port
                for port in range (start_port, end_port +1)
            }

            for future in concurrent.futures.as_completed(future_to_port):
                result= future.result()
                if result:
                    port, banner= result
                    self.open_ports[port] = banner
                    service = self._identity_service(port, banner)
                    print(f"[+] { target}:{port} OPEN | Service: {service}")

        self._generate_report(target)

    def _identity_service(self, port, banner):
        common_services = {
            21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 80: "HTTP",
            443: "HTTPS", 445: "SMB", 3389: "RDP"
        }

        service = common_services.get(port, "UNKNOWN")

        if "Apache" in banner:
            service = "Apache HTTPD"
        elif "nginx" in banner:
            service = "nginx"
        elif "SSH" in banner:
            service = "OpenSSH "

        return service

    def _generate_report(self, target):
        print(f"\n{'='*50}")
        print(f"SCAN REPORT: {target}")
        print(f"Timestamp: {datetime.now()}")
        print(f"Open ports: {len(self.open_ports)}")

        for port, banner in sorted (self.open_ports.items()):
            service = self._identity_service(port, banner)
            print(f" {port}/TCP - {service}")

            if banner != "BANNER UNAVAILABLE":
                banner_lines = banner.split('\n')
                if banner_lines:
                    print (f" Banner:{banner_lines[0][:80]}...")

        print(f"{'='*50}")

if __name__ == "__main__":
    TARGET = "127.0.0.1"
    START_PORT = 1
    END_PORT = 1024

    scanner = PortScanner(timeout=0.5, max_threads=200)
    scanner.scan_range(TARGET, START_PORT, END_PORT)