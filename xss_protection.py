import re
import html
from typing import List, Tuple

class XSSProtection:
    """
    XSS (Cross-Site Scripting) Protection and Detection Class
    Detects and sanitizes potentially malicious input that could lead to XSS attacks
    """
    
    # Common XSS patterns
    XSS_PATTERNS = [
        r'<\s*script[^>]*>.*?</\s*script\s*>',  # Script tags
        r'on\w+\s*=',  # Event handlers (onclick, onload, etc)
        r'javascript\s*:',  # JavaScript protocol
        r'<\s*iframe[^>]*>',  # iFrame tags
        r'<\s*object[^>]*>',  # Object tags
        r'<\s*embed[^>]*>',  # Embed tags
        r'<\s*img[^>]*on\w+',  # Image with event handlers
        r'<\s*svg[^>]*on\w+',  # SVG with event handlers
        r'expression\s*\(',  # CSS expression
        r'vbscript\s*:',  # VBScript protocol
    ]
    
    DANGEROUS_TAGS = [
        'script', 'iframe', 'object', 'embed', 'frame', 'frameset',
        'link', 'meta', 'style', 'form', 'input', 'button'
    ]
    
    DANGEROUS_ATTRIBUTES = [
        'onclick', 'onload', 'onerror', 'onmouseover', 'onmouseout',
        'onchange', 'onsubmit', 'onfocus', 'onblur', 'onkeydown',
        'onkeyup', 'onmouseenter', 'onmouseleave', 'onwheel'
    ]
    
    @staticmethod
    def detect_xss(user_input: str) -> Tuple[bool, List[str]]:
        """
        Detect potential XSS attacks in user input
        
        Args:
            user_input: String to check for XSS patterns
            
        Returns:
            Tuple of (is_dangerous, detected_patterns)
        """
        if not user_input:
            return False, []
        
        detected = []
        
        # Check against XSS patterns
        for pattern in XSSProtection.XSS_PATTERNS:
            if re.search(pattern, user_input, re.IGNORECASE | re.DOTALL):
                detected.append(f"Pattern: {pattern[:50]}...")
        
        # Check for dangerous tags
        for tag in XSSProtection.DANGEROUS_TAGS:
            if re.search(rf'<\s*{tag}[\s>]', user_input, re.IGNORECASE):
                detected.append(f"Dangerous tag: <{tag}>")
        
        # Check for dangerous attributes
        for attr in XSSProtection.DANGEROUS_ATTRIBUTES:
            if re.search(rf'{attr}\s*=\s*['\"]?[^'\"]*['\"]?', user_input, re.IGNORECASE):
                detected.append(f"Dangerous attribute: {attr}")
        
        return len(detected) > 0, detected
    
    @staticmethod
    def sanitize(user_input: str) -> str:
        """
        Sanitize user input by removing/escaping potential XSS vectors
        
        Args:
            user_input: String to sanitize
            
        Returns:
            Sanitized string
        """
        if not user_input:
            return ""
        
        # Remove script tags and content
        sanitized = re.sub(r'<\s*script[^>]*>.*?</\s*script\s*>', '', user_input, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove event handlers
        sanitized = re.sub(r'on\w+\s*=\s*['\"]?[^'\"]*['\"]?', '', sanitized, flags=re.IGNORECASE)
        
        # Remove dangerous tags
        for tag in XSSProtection.DANGEROUS_TAGS:
            sanitized = re.sub(rf'<\s*{tag}[^>]*>', '', sanitized, flags=re.IGNORECASE)
            sanitized = re.sub(rf'</\s*{tag}\s*>', '', sanitized, flags=re.IGNORECASE)
        
        # Remove javascript and vbscript protocols
        sanitized = re.sub(r'javascript\s*:', '', sanitized, flags=re.IGNORECASE)
        sanitized = re.sub(r'vbscript\s*:', '', sanitized, flags=re.IGNORECASE)
        
        # HTML escape remaining content
        sanitized = html.escape(sanitized)
        
        return sanitized
    
    @staticmethod
    def escape_html(text: str) -> str:
        """
        Escape HTML special characters
        
        Args:
            text: String to escape
            
        Returns:
            HTML-escaped string
        """
        return html.escape(text)
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate if URL is safe (not containing XSS vectors)
        
        Args:
            url: URL string to validate
            
        Returns:
            True if URL appears safe, False otherwise
        """
        dangerous_protocols = ['javascript:', 'data:', 'vbscript:']
        url_lower = url.lower().strip()
        
        for protocol in dangerous_protocols:
            if url_lower.startswith(protocol):
                return False
        
        is_dangerous, _ = XSSProtection.detect_xss(url)
        return not is_dangerous


# Example usage and testing
if __name__ == "__main__":
    print("=" * 60)
    print("XSS Protection Script - Attack Detection & Sanitization")
    print("=" * 60)
    
    test_cases = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=\"alert('XSS')\">",
        "<svg onload=\"alert('XSS')\"></svg>",
        "Normal user input without attacks",
        "<iframe src=\"evil.com\"></iframe>",
        "javascript:alert('XSS')",
        "<div onclick=\"malicious()\">Click me</div>",
        "Safe text with <b>bold</b> tags",
    ]
    
    print("\n[TEST RESULTS]")
    for i, test in enumerate(test_cases, 1):
        is_dangerous, patterns = XSSProtection.detect_xss(test)
        sanitized = XSSProtection.sanitize(test)
        
        print(f"\nTest {i}:")
        print(f"  Input: {test[:50]}...")
        print(f"  Dangerous: {is_dangerous}")
        if patterns:
            print(f"  Detected: {patterns}")
        print(f"  Sanitized: {sanitized[:50]}...")
    
    print("\n" + "=" * 60)
    print("Testing URL validation:")
    print("=" * 60)
    
    urls = [
        "https://example.com",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
        "http://safe-site.com/page",
    ]
    
    for url in urls:
        is_safe = XSSProtection.validate_url(url)
        print(f"URL: {url}")
        print(f"Safe: {is_safe}\n")
