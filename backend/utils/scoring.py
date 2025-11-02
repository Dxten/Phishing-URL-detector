from typing import Dict, List
from config import Config


class ScoringSystem:
    """Advanced scoring system for threat assessment"""
    
    def __init__(self):
        self.weights = Config.get_scoring_weights()
        self.threshold_phishing = Config.PHISHING_THRESHOLD
        self.threshold_suspicious = Config.SUSPICIOUS_THRESHOLD
    
    def calculate_score(self, threats: List[Dict]) -> int:
        """Calculate total score from detected threats"""
        total = 0
        for threat in threats:
            total += threat.get('score', 0)
        return total
    
    def get_risk_level(self, score: int) -> str:
        """Determine risk level based on score"""
        if score >= self.threshold_phishing:
            return 'dangerous'
        elif score >= self.threshold_suspicious:
            return 'suspicious'
        else:
            return 'safe'
    
    def get_confidence(self, score: int, risk_level: str) -> float:
        """Calculate confidence level (0.0 to 1.0)"""
        if risk_level == 'dangerous':
            return min(0.95, 0.5 + (score / 20))
        elif risk_level == 'suspicious':
            return 0.3 + (score / 30)
        else:
            return max(0.05, 1.0 - (score / 10))
    
    def get_recommendation(self, risk_level: str) -> Dict:
        """Get user recommendation based on risk level"""
        recommendations = {
            'dangerous': {
                'action': 'BLOCK',
                'message': 'Do not visit this URL. It shows strong signs of phishing.',
                'color': 'red',
                'icon': '🚫'
            },
            'suspicious': {
                'action': 'WARN',
                'message': 'Exercise caution. This URL has suspicious characteristics.',
                'color': 'orange',
                'icon': '⚠️'
            },
            'safe': {
                'action': 'ALLOW',
                'message': 'This URL appears safe based on our analysis.',
                'color': 'green',
                'icon': '✅'
            },
            'error': {
                'action': 'UNKNOWN',
                'message': 'Unable to analyze this URL.',
                'color': 'gray',
                'icon': '❓'
            }
        }
        return recommendations.get(risk_level, recommendations['error'])
    
    def prioritize_threats(self, threats: List[Dict]) -> List[Dict]:
        """Sort threats by severity"""
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return sorted(threats, key=lambda x: severity_order.get(x.get('severity', 'low'), 4))
    
    def get_threat_summary(self, threats: List[Dict]) -> Dict:
        """Generate summary of threats"""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'total': len(threats)
        }
        
        for threat in threats:
            severity = threat.get('severity', 'low')
            if severity in summary:
                summary[severity] += 1
        
        return summary