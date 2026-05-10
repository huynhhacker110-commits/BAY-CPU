import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import json
from datetime import datetime

class AIDDoSDetector:
    """
    Module 1: AI DDoS Detection
    Uses machine learning to detect DDoS attacks in real-time
    """
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.threat_log = []
        
    def extract_features(self, request_data):
        """
        Extract features from HTTP requests
        Features: request_rate, packet_size, unique_ips, protocol_type
        """
        features = [
            request_data.get('request_rate', 0),
            request_data.get('packet_size', 0),
            request_data.get('unique_ips', 0),
            request_data.get('protocol_type', 0),  # 0=HTTP, 1=HTTPS, 2=UDP
            request_data.get('response_time', 0),
            request_data.get('error_rate', 0),
        ]
        return np.array(features).reshape(1, -1)
    
    def train(self, training_data):
        """
        Train the AI model with historical data
        training_data: list of request dictionaries
        """
        features_list = []
        for data in training_data:
            features = self.extract_features(data)
            features_list.append(features[0])
        
        X = np.array(features_list)
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        print("[✓] AI DDoS Detector trained successfully")
    
    def detect(self, request_data):
        """
        Detect if incoming request is a DDoS attack
        Returns: (is_attack, confidence_score)
        """
        if not self.is_trained:
            print("[!] Model not trained yet")
            return False, 0.0
        
        features = self.extract_features(request_data)
        features_scaled = self.scaler.transform(features)
        prediction = self.model.predict(features_scaled)[0]
        anomaly_score = -self.model.score_samples(features_scaled)[0]
        
        is_attack = prediction == -1
        confidence = min(anomaly_score / 2, 1.0)  # Normalize to 0-1
        
        if is_attack:
            self.threat_log.append({
                'timestamp': datetime.now().isoformat(),
                'confidence': confidence,
                'source_ip': request_data.get('source_ip', 'unknown')
            })
        
        return is_attack, confidence
    
    def get_threat_report(self):
        """
        Get summary of detected threats
        """
        return {
            'total_threats': len(self.threat_log),
            'recent_threats': self.threat_log[-10:] if self.threat_log else [],
            'avg_confidence': np.mean([t['confidence'] for t in self.threat_log]) if self.threat_log else 0
        }


if __name__ == "__main__":
    detector = AIDDoSDetector()
    
    # Example training data
    training_data = [
        {'request_rate': 10, 'packet_size': 512, 'unique_ips': 5, 'protocol_type': 0, 'response_time': 0.1, 'error_rate': 0.01},
        {'request_rate': 12, 'packet_size': 520, 'unique_ips': 6, 'protocol_type': 0, 'response_time': 0.12, 'error_rate': 0.02},
        {'request_rate': 15, 'packet_size': 530, 'unique_ips': 7, 'protocol_type': 1, 'response_time': 0.15, 'error_rate': 0.03},
    ]
    
    detector.train(training_data)
    
    # Test detection
    test_request = {'request_rate': 1000, 'packet_size': 100, 'unique_ips': 500, 'protocol_type': 2, 'response_time': 5.0, 'error_rate': 0.8}
    is_attack, confidence = detector.detect(test_request)
    print(f"\n[Detection Result] Attack: {is_attack}, Confidence: {confidence:.2%}")
    print(f"[Threat Report] {detector.get_threat_report()}")
