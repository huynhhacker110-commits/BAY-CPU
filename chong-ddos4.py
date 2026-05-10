import requests
import json
from datetime import datetime

class CloudflareIntegration:
    """
    Module 4: Cloudflare Integration
    Integrates with Cloudflare API for advanced DDoS protection
    """
    
    def __init__(self, api_token, zone_id, email=None):
        self.api_token = api_token
        self.zone_id = zone_id
        self.email = email
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        }
        self.action_log = []
    
    def get_zone_settings(self):
        """
        Get current zone DDoS protection settings
        """
        url = f"{self.base_url}/zones/{self.zone_id}/settings"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()['result']
            else:
                print(f"[!] Error: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            print(f"[!] Exception: {e}")
            return None
    
    def enable_ddos_protection(self, level='high'):
        """
        Enable DDoS protection at specified level
        Levels: 'low', 'medium', 'high', 'i_m_under_attack'
        """
        url = f"{self.base_url}/zones/{self.zone_id}/settings/security_level"
        data = {"value": level}
        
        try:
            response = requests.patch(url, headers=self.headers, json=data, timeout=10)
            if response.status_code == 200:
                self.action_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'ENABLE_DDOS_PROTECTION',
                    'level': level,
                    'status': 'SUCCESS'
                })
                print(f"[✓] DDoS protection enabled: {level}")
                return True
            else:
                print(f"[!] Error: {response.status_code}")
                return False
        except Exception as e:
            print(f"[!] Exception: {e}")
            return False
    
    def add_ip_to_whitelist(self, ip_address):
        """
        Add IP address to Cloudflare whitelist
        """
        url = f"{self.base_url}/zones/{self.zone_id}/firewall/access_rules/rules"
        data = {
            "mode": "whitelist",
            "configuration": {"target": "ip", "value": ip_address},
            "notes": f"Whitelisted by AI Protection System"
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=10)
            if response.status_code == 200:
                self.action_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'WHITELIST_IP',
                    'ip': ip_address,
                    'status': 'SUCCESS'
                })
                print(f"[✓] IP {ip_address} whitelisted")
                return True
            else:
                return False
        except Exception as e:
            print(f"[!] Exception: {e}")
            return False
    
    def add_ip_to_blacklist(self, ip_address):
        """
        Add IP address to Cloudflare blacklist
        """
        url = f"{self.base_url}/zones/{self.zone_id}/firewall/access_rules/rules"
        data = {
            "mode": "block",
            "configuration": {"target": "ip", "value": ip_address},
            "notes": f"Blocked by AI DDoS Detection"
        }
        
        try:
            response = requests.post(url, headers=self.headers, json=data, timeout=10)
            if response.status_code == 200:
                self.action_log.append({
                    'timestamp': datetime.now().isoformat(),
                    'action': 'BLACKLIST_IP',
                    'ip': ip_address,
                    'status': 'SUCCESS'
                })
                print(f"[🚫] IP {ip_address} blacklisted")
                return True
            else:
                return False
        except Exception as e:
            print(f"[!] Exception: {e}")
            return False
    
    def get_analytics(self, start_time, end_time):
        """
        Get DDoS analytics for specified time period
        """
        url = f"{self.base_url}/zones/{self.zone_id}/analytics/http_requests_by_1h_bot"
        params = {
            "since": start_time,
            "until": end_time,
            "continuous": True
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()['result']
            else:
                return None
        except Exception as e:
            print(f"[!] Exception: {e}")
            return None
    
    def get_action_log(self):
        """
        Get log of all Cloudflare integration actions
        """
        return {
            'total_actions': len(self.action_log),
            'recent_actions': self.action_log[-10:]
        }


if __name__ == "__main__":
    # Note: Replace with actual Cloudflare credentials
    api_token = "YOUR_CLOUDFLARE_API_TOKEN"
    zone_id = "YOUR_ZONE_ID"
    
    cf = CloudflareIntegration(api_token, zone_id)
    
    print("[Cloudflare Integration Test]")
    print("[Note] Replace credentials with actual Cloudflare API tokens")
    print(f"\nAvailable methods:")
    print("- get_zone_settings()")
    print("- enable_ddos_protection(level)")
    print("- add_ip_to_whitelist(ip)")
    print("- add_ip_to_blacklist(ip)")
    print("- get_analytics(start_time, end_time)")
    print("- get_action_log()")
