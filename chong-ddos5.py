import pickle
import os
from datetime import datetime
from collections import defaultdict
import numpy as np

class AILearningSystem:
    """
    Module 5: AI Learning System
    Adaptive learning system that improves DDoS detection over time
    """
    
    def __init__(self, model_path='./ai_models'):
        self.model_path = model_path
        self.learning_history = []
        self.attack_patterns = defaultdict(int)
        self.normal_patterns = defaultdict(int)
        self.model_version = 1.0
        self.confidence_threshold = 0.7
        self.false_positive_rate = 0.0
        self.false_negative_rate = 0.0
        
        if not os.path.exists(model_path):
            os.makedirs(model_path)
    
    def log_event(self, event_type, data, is_attack, confidence):
        """
        Log events for learning
        event_type: 'request', 'blocked', 'allowed', 'feedback'
        """
        event_record = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'data': data,
            'is_attack': is_attack,
            'confidence': confidence
        }
        self.learning_history.append(event_record)
        
        # Update pattern recognition
        pattern_key = str(hash(str(data)))
        if is_attack:
            self.attack_patterns[pattern_key] += 1
        else:
            self.normal_patterns[pattern_key] += 1
    
    def analyze_feedback(self, prediction, actual, confidence):
        """
        Analyze feedback to identify false positives/negatives
        Returns: (feedback_type, learning_value)
        """
        if prediction == actual:
            feedback_type = 'TRUE_POSITIVE' if prediction else 'TRUE_NEGATIVE'
            learning_value = 0.1  # Positive reinforcement
        else:
            if prediction and not actual:
                feedback_type = 'FALSE_POSITIVE'
                self.false_positive_rate += 0.01
                learning_value = -0.2
            else:
                feedback_type = 'FALSE_NEGATIVE'
                self.false_negative_rate += 0.01
                learning_value = -0.5  # More severe penalty
        
        self.log_event('feedback', {'prediction': prediction, 'actual': actual}, actual, confidence)
        return feedback_type, learning_value
    
    def adapt_threshold(self):
        """
        Adaptively adjust confidence threshold based on false rates
        """
        if self.false_positive_rate > 0.2:
            self.confidence_threshold += 0.05
            print(f"[⚙️] Increased threshold to {self.confidence_threshold:.2f} (reduce FP)")
        
        if self.false_negative_rate > 0.1:
            self.confidence_threshold -= 0.05
            print(f"[⚙️] Decreased threshold to {self.confidence_threshold:.2f} (reduce FN)")
        
        # Clamp between 0.5 and 0.95
        self.confidence_threshold = max(0.5, min(0.95, self.confidence_threshold))
    
    def get_attack_patterns(self, top_n=5):
        """
        Get most common attack patterns
        """
        sorted_patterns = sorted(
            self.attack_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_patterns[:top_n]
    
    def get_learning_insights(self):
        """
        Generate learning insights from collected data
        """
        total_events = len(self.learning_history)
        attack_events = sum(1 for e in self.learning_history if e['is_attack'])
        
        insights = {
            'total_events_analyzed': total_events,
            'attack_events': attack_events,
            'normal_events': total_events - attack_events,
            'attack_rate': (attack_events / total_events * 100) if total_events > 0 else 0,
            'current_threshold': self.confidence_threshold,
            'false_positive_rate': self.false_positive_rate,
            'false_negative_rate': self.false_negative_rate,
            'model_version': self.model_version,
            'top_attack_patterns': self.get_attack_patterns(3),
            'recent_events': self.learning_history[-5:]
        }
        return insights
    
    def save_model(self, filename='ai_model.pkl'):
        """
        Save trained model and learning data
        """
        filepath = os.path.join(self.model_path, filename)
        try:
            with open(filepath, 'wb') as f:
                pickle.dump({
                    'learning_history': self.learning_history,
                    'attack_patterns': self.attack_patterns,
                    'normal_patterns': self.normal_patterns,
                    'model_version': self.model_version,
                    'confidence_threshold': self.confidence_threshold,
                    'false_positive_rate': self.false_positive_rate,
                    'false_negative_rate': self.false_negative_rate
                }, f)
            print(f"[✓] Model saved to {filepath}")
            return True
        except Exception as e:
            print(f"[!] Error saving model: {e}")
            return False
    
    def load_model(self, filename='ai_model.pkl'):
        """
        Load previously trained model and learning data
        """
        filepath = os.path.join(self.model_path, filename)
        try:
            with open(filepath, 'rb') as f:
                data = pickle.load(f)
                self.learning_history = data['learning_history']
                self.attack_patterns = data['attack_patterns']
                self.normal_patterns = data['normal_patterns']
                self.model_version = data['model_version']
                self.confidence_threshold = data['confidence_threshold']
                self.false_positive_rate = data['false_positive_rate']
                self.false_negative_rate = data['false_negative_rate']
            print(f"[✓] Model loaded from {filepath}")
            return True
        except Exception as e:
            print(f"[!] Error loading model: {e}")
            return False
    
    def update_model_version(self):
        """
        Increment model version after significant improvements
        """
        self.model_version += 0.1
        print(f"[🔄] Model updated to version {self.model_version:.1f}")
        self.save_model()


if __name__ == "__main__":
    learning_system = AILearningSystem()
    
    print("[Test 1] Log some events")
    learning_system.log_event('request', {'ip': '192.168.1.1', 'rate': 10}, False, 0.2)
    learning_system.log_event('request', {'ip': '10.0.0.1', 'rate': 1000}, True, 0.95)
    learning_system.log_event('blocked', {'ip': '10.0.0.1'}, True, 0.92)
    
    print("\n[Test 2] Analyze feedback")
    feedback1, value1 = learning_system.analyze_feedback(True, True, 0.95)
    print(f"Feedback: {feedback1}, Learning Value: {value1}")
    
    feedback2, value2 = learning_system.analyze_feedback(True, False, 0.85)
    print(f"Feedback: {feedback2}, Learning Value: {value2}")
    
    print("\n[Test 3] Adapt threshold")
    learning_system.adapt_threshold()
    
    print("\n[Test 4] Get insights")
    insights = learning_system.get_learning_insights()
    print(f"\nInsights:\n{json.dumps(insights, indent=2)}")
    
    print("\n[Test 5] Save model")
    learning_system.save_model()
