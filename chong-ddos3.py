import random
import string
from datetime import datetime, timedelta
import hashlib
import json

class CAPTCHAHandler:
    """
    Module 3: CAPTCHA Handler
    Manages CAPTCHA generation, validation, and session management
    """
    
    def __init__(self, captcha_expiry=300, max_attempts=3):
        self.captcha_expiry = captcha_expiry  # seconds
        self.max_attempts = max_attempts
        self.active_captchas = {}  # {session_id: captcha_data}
        self.validation_log = []
        
    def generate_captcha(self, ip_address):
        """
        Generate a new CAPTCHA challenge
        Returns: (session_id, captcha_text, captcha_hash)
        """
        # Generate session ID
        session_id = hashlib.sha256(
            (ip_address + str(datetime.now()) + str(random.random())).encode()
        ).hexdigest()[:16]
        
        # Generate CAPTCHA text (6 alphanumeric characters)
        captcha_text = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
        captcha_hash = hashlib.sha256(captcha_text.encode()).hexdigest()
        
        # Store CAPTCHA data
        self.active_captchas[session_id] = {
            'captcha_hash': captcha_hash,
            'ip_address': ip_address,
            'created_at': datetime.now(),
            'attempts': 0,
            'solved': False
        }
        
        return session_id, captcha_text, captcha_hash
    
    def validate_captcha(self, session_id, user_answer, ip_address):
        """
        Validate CAPTCHA response
        Returns: (is_valid, message, session_data)
        """
        if session_id not in self.active_captchas:
            return False, 'INVALID_SESSION', None
        
        captcha_data = self.active_captchas[session_id]
        
        # Check if expired
        time_elapsed = (datetime.now() - captcha_data['created_at']).total_seconds()
        if time_elapsed > self.captcha_expiry:
            del self.active_captchas[session_id]
            return False, 'CAPTCHA_EXPIRED', None
        
        # Check if IP matches
        if captcha_data['ip_address'] != ip_address:
            return False, 'IP_MISMATCH', None
        
        # Check attempts
        if captcha_data['attempts'] >= self.max_attempts:
            del self.active_captchas[session_id]
            return False, 'MAX_ATTEMPTS_EXCEEDED', None
        
        # Validate answer
        user_hash = hashlib.sha256(user_answer.upper().encode()).hexdigest()
        is_valid = user_hash == captcha_data['captcha_hash']
        
        captcha_data['attempts'] += 1
        
        if is_valid:
            captcha_data['solved'] = True
            del self.active_captchas[session_id]
        
        self.validation_log.append({
            'timestamp': datetime.now().isoformat(),
            'session_id': session_id,
            'ip_address': ip_address,
            'is_valid': is_valid,
            'attempt': captcha_data['attempts']
        })
        
        return is_valid, 'VALID' if is_valid else 'INVALID_ANSWER', captcha_data
    
    def cleanup_expired(self):
        """
        Remove expired CAPTCHA sessions
        """
        now = datetime.now()
        expired_sessions = []
        
        for session_id, data in self.active_captchas.items():
            if (now - data['created_at']).total_seconds() > self.captcha_expiry:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.active_captchas[session_id]
        
        return len(expired_sessions)
    
    def get_stats(self):
        """
        Get CAPTCHA statistics
        """
        total_validations = len(self.validation_log)
        successful = sum(1 for log in self.validation_log if log['is_valid'])
        
        return {
            'active_captchas': len(self.active_captchas),
            'total_validations': total_validations,
            'successful_solves': successful,
            'success_rate': (successful / total_validations * 100) if total_validations > 0 else 0,
            'recent_validations': self.validation_log[-5:]
        }


if __name__ == "__main__":
    captcha = CAPTCHAHandler()
    
    print("[Test 1] Generate CAPTCHA")
    session_id, captcha_text, captcha_hash = captcha.generate_captcha('192.168.1.100')
    print(f"Session: {session_id}")
    print(f"CAPTCHA: {captcha_text} (hash: {captcha_hash[:16]}...)")
    
    print("\n[Test 2] Validate correct answer")
    is_valid, msg, data = captcha.validate_captcha(session_id, captcha_text, '192.168.1.100')
    print(f"Result: {is_valid}, Message: {msg}")
    
    print("\n[Test 3] Generate and fail multiple times")
    session_id2, captcha_text2, _ = captcha.generate_captcha('192.168.1.101')
    for i in range(4):
        is_valid, msg, _ = captcha.validate_captcha(session_id2, 'WRONG', '192.168.1.101')
        print(f"Attempt {i+1}: {msg}")
    
    print(f"\n[Stats] {captcha.get_stats()}")
