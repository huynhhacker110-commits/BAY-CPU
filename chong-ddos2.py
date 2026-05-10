import time
from collections import defaultdict, deque
from datetime import datetime, timedelta

class AIDDoSMitigator:
    """
    Module 2: AI DDoS Mitigation
    Implements adaptive rate limiting and IP blocking strategies
    """
    
    def __init__(self, max_requests_per_minute=100, block_duration=300):
        self.max_requests_per_minute = max_requests_per_minute
        self.block_duration = block_duration  # seconds
        self.ip_requests = defaultdict(deque)
        self.blocked_ips = {}  # {ip: unblock_time}
        self.mitigation_log = []
        
    def is_ip_blocked(self, ip_address):
        """
        Check if an IP is currently blocked
        """
        if ip_address in self.blocked_ips:
            if time.time() < self.blocked_ips[ip_address]:
                return True
            else:
                del self.blocked_ips[ip_address]
        return False
    
    def block_ip(self, ip_address, duration=None):
        """
        Block an IP address for specified duration
        """
        if duration is None:
            duration = self.block_duration
        
        unblock_time = time.time() + duration
        self.blocked_ips[ip_address] = unblock_time
        
        self.mitigation_log.append({
            'timestamp': datetime.now().isoformat(),
            'action': 'BLOCK_IP',
            'target': ip_address,
            'duration': duration
        })
        print(f"[🚫] IP {ip_address} blocked for {duration}s")
    
    def unblock_ip(self, ip_address):
        """
        Manually unblock an IP address
        """
        if ip_address in self.blocked_ips:
            del self.blocked_ips[ip_address]
            self.mitigation_log.append({
                'timestamp': datetime.now().isoformat(),
                'action': 'UNBLOCK_IP',
                'target': ip_address
            })
            print(f"[✓] IP {ip_address} unblocked")
    
    def check_rate_limit(self, ip_address):
        """
        Check if IP has exceeded rate limit
        Returns: (allowed, requests_count, limit_remaining)
        """
        current_time = time.time()
        one_minute_ago = current_time - 60
        
        # Clean old requests
        while self.ip_requests[ip_address] and self.ip_requests[ip_address][0] < one_minute_ago:
            self.ip_requests[ip_address].popleft()
        
        request_count = len(self.ip_requests[ip_address])
        
        if request_count >= self.max_requests_per_minute:
            # Adaptive blocking - increase duration on repeated violations
            violation_count = sum(1 for log in self.mitigation_log if log['target'] == ip_address)
            duration = self.block_duration * (1 + violation_count * 0.5)
            self.block_ip(ip_address, duration)
            return False, request_count, 0
        
        # Record this request
        self.ip_requests[ip_address].append(current_time)
        limit_remaining = self.max_requests_per_minute - request_count - 1
        
        return True, request_count, limit_remaining
    
    def handle_request(self, ip_address, request_data):
        """
        Main handler for incoming requests
        Returns: (allowed, reason, mitigation_action)
        """
        # Check if already blocked
        if self.is_ip_blocked(ip_address):
            return False, 'IP_BLOCKED', 'SERVE_CAPTCHA'
        
        # Check rate limit
        allowed, count, remaining = self.check_rate_limit(ip_address)
        
        if not allowed:
            return False, 'RATE_LIMIT_EXCEEDED', 'SERVE_CAPTCHA_AND_BLOCK'
        
        return True, 'OK', 'ALLOW_REQUEST'
    
    def get_mitigation_stats(self):
        """
        Get statistics on mitigation actions
        """
        blocked_count = len(self.blocked_ips)
        total_actions = len(self.mitigation_log)
        
        return {
            'currently_blocked_ips': blocked_count,
            'total_mitigation_actions': total_actions,
            'blocked_ips_list': list(self.blocked_ips.keys()),
            'recent_actions': self.mitigation_log[-10:]
        }


if __name__ == "__main__":
    mitigator = AIDDoSMitigator(max_requests_per_minute=5)
    
    # Simulate requests
    print("[Test 1] Normal requests")
    for i in range(3):
        allowed, reason, action = mitigator.handle_request('192.168.1.100', {})
        print(f"Request {i+1}: Allowed={allowed}, Reason={reason}")
    
    print("\n[Test 2] Rate limit exceeded")
    for i in range(4):
        allowed, reason, action = mitigator.handle_request('192.168.1.100', {})
        print(f"Request {i+4}: Allowed={allowed}, Reason={reason}, Action={action}")
    
    print(f"\n[Stats] {mitigator.get_mitigation_stats()}")
