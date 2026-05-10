import time
import socket
from collections import defaultdict

class DDoSProtection:
    def __init__(self, max_requests_per_minute):
        self.max_requests = max_requests_per_minute
        self.request_count = defaultdict(int)
        self.blocked_ips = set()

    def check_request(self, ip):
        if ip in self.blocked_ips:
            print(f"IP {ip} is blocked.")
            return False

        self.request_count[ip] += 1
        if self.request_count[ip] > self.max_requests:
            self.block_ip(ip)
            return False
        return True

    def block_ip(self, ip):
        print(f"Blocking IP {ip} due to DDoS attack!")
        self.blocked_ips.add(ip)

    def reset_counts(self):
        while True:
            time.sleep(60)
            self.request_count.clear()
            print("Request counts have been reset.")

if __name__ == '__main__':
    ddos_protection = DDoSProtection(max_requests_per_minute=100)
    
    # Start the reset counts in a separate thread
    import threading
    threading.Thread(target=ddos_protection.reset_counts, daemon=True).start()
    
    # Simulate incoming requests
    while True:
        incoming_ip = socket.gethostbyname(socket.gethostname())
        if ddos_protection.check_request(incoming_ip):
            print(f"Request from {incoming_ip} is allowed.")
        else:
            print(f"Request from {incoming_ip} is denied.")
        time.sleep(0.5) # Simulate time between requests
