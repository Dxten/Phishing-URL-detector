from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json
from pathlib import Path

from detector import PhishingDetector
from utils.validators import is_valid_url, extract_domain
from utils.scoring import ScoringSystem
from utils.blacklist_updater import BlacklistUpdater
from config import Config

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize detector
Config.ensure_directories()
detector = PhishingDetector()
scoring = ScoringSystem()

# Initialize blacklist updater
updater = BlacklistUpdater()

# Detection history
history_file = Config.DETECTION_LOG

# Simple URL validator class to maintain compatibility
class URLValidator:
    @staticmethod
    def sanitize_url(url):
        return url.strip()
    
    @staticmethod
    def is_valid_url(url):
        return is_valid_url(url)
    
    @staticmethod
    def extract_components(url):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'path': parsed.path,
            'query': parsed.query,
            'fragment': parsed.fragment
        }

validator = URLValidator()


@app.route('/')
def index():
    """API information"""
    return jsonify({
        'name': 'Phishing URL Detector API',
        'version': '1.0.0',
        'endpoints': {
            '/api/check': 'POST - Check if URL is phishing',
            '/api/batch': 'POST - Check multiple URLs',
            '/api/stats': 'GET - Get detection statistics',
            '/api/history': 'GET - Get detection history',
            '/api/update-blacklist': 'POST - Update blacklist manually',
            '/api/report': 'POST - Report a phishing URL',
            '/api/health': 'GET - Health check'
        }
    })


@app.route('/api/check', methods=['POST'])
def check_url():
    """Check single URL for phishing"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'error': 'URL is required'
            }), 400
        
        # Sanitize URL
        url = URLValidator.sanitize_url(url)
        
        # Validate URL
        if not URLValidator.is_valid_url(url):
            return jsonify({
                'error': 'Invalid URL format'
            }), 400
        
        # Analyze URL
        result = detector.analyze_url(url)
        
        # Add recommendation
        result['recommendation'] = scoring.get_recommendation(result['risk_level'])
        
        # Add threat summary
        result['threat_summary'] = scoring.get_threat_summary(result['threats_detected'])
        
        # Save to history
        _save_to_history(result)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/batch', methods=['POST'])
def check_batch():
    """Check multiple URLs"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls or not isinstance(urls, list):
            return jsonify({
                'error': 'URLs array is required'
            }), 400
        
        if len(urls) > 100:
            return jsonify({
                'error': 'Maximum 100 URLs per batch'
            }), 400
        
        results = []
        for url in urls:
            url = URLValidator.sanitize_url(url.strip())
            if URLValidator.is_valid_url(url):
                result = detector.analyze_url(url)
                result['recommendation'] = scoring.get_recommendation(result['risk_level'])
                results.append(result)
        
        return jsonify({
            'total': len(results),
            'results': results,
            'summary': {
                'safe': sum(1 for r in results if r['risk_level'] == 'safe'),
                'suspicious': sum(1 for r in results if r['risk_level'] == 'suspicious'),
                'dangerous': sum(1 for r in results if r['risk_level'] == 'dangerous')
            }
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get detection statistics"""
    try:
        stats = detector.get_statistics()
        
        # Calculate percentages
        total = stats['total_analyzed']
        if total > 0:
            stats['phishing_percentage'] = round((stats['phishing_detected'] / total) * 100, 2)
            stats['safe_percentage'] = round((stats['safe_urls'] / total) * 100, 2)
            stats['suspicious_percentage'] = round((stats['suspicious_urls'] / total) * 100, 2)
            stats['cache_hit_rate'] = round((stats['cache_hits'] / total) * 100, 2)
        
        return jsonify(stats)
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/history', methods=['GET'])
def get_history():
    """Get detection history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        risk_level = request.args.get('risk_level', None)
        
        # Ensure logs directory exists
        Config.LOGS_DIR.mkdir(exist_ok=True)
        
        # If file doesn't exist or is empty, return empty history
        if not history_file.exists():
            return jsonify({'history': []})
        
        # Check if file is empty
        if history_file.stat().st_size == 0:
            return jsonify({'history': []})
        
        with open(history_file, 'r') as f:
            content = f.read().strip()
            if not content:
                return jsonify({'history': []})
            
            history = json.loads(content)
        
        # Filter by risk level if specified
        if risk_level:
            history = [h for h in history if h.get('risk_level') == risk_level]
        
        # Return most recent entries
        history = history[-limit:]
        history.reverse()
        
        return jsonify({
            'total': len(history),
            'history': history
        })
    
    except json.JSONDecodeError:
        # Handle corrupted JSON file
        return jsonify({'history': []})
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/update-blacklist', methods=['POST'])
def update_blacklist():
    """Manually trigger blacklist update"""
    try:
        success = updater.update_blacklist()
        
        if success:
            # Reload detector's blacklist
            detector._load_blacklist()
            
            return jsonify({
                'message': 'Blacklist updated successfully',
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({
                'error': 'Failed to update blacklist'
            }), 500
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/report', methods=['POST'])
def report_phishing():
    """Report a phishing URL"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        reporter_comment = data.get('comment', '')
        
        if not url:
            return jsonify({
                'error': 'URL is required'
            }), 400
        
        url = URLValidator.sanitize_url(url)
        
        if not URLValidator.is_valid_url(url):
            return jsonify({
                'error': 'Invalid URL format'
            }), 400
        
        # Extract domain and add to blacklist
        from urllib.parse import urlparse
        import tldextract
        
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}".lower()
        
        detector.add_to_blacklist(domain)
        
        # Save report
        report_file = Config.LOGS_DIR / 'reported_urls.json'
        reports = []
        
        if report_file.exists():
            with open(report_file, 'r') as f:
                reports = json.load(f)
        
        reports.append({
            'url': url,
            'domain': domain,
            'comment': reporter_comment,
            'timestamp': datetime.now().isoformat(),
            'reporter_ip': request.remote_addr
        })
        
        with open(report_file, 'w') as f:
            json.dump(reports, f, indent=2)
        
        # Append to blacklist file
        with open(Config.PHISHING_URLS_FILE, 'a') as f:
            f.write(f"{domain}\n")
        
        return jsonify({
            'message': 'Thank you for reporting. URL has been added to blacklist.',
            'domain': domain
        })
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'blacklist_size': detector.blacklist_hashset.size(),
        'whitelist_size': detector.whitelist.size(),
        'cache_size': len(detector.cache.cache)
    })


@app.route('/api/clear-cache', methods=['POST'])
def clear_cache():
    """Clear detection cache"""
    try:
        detector.clear_cache()
        return jsonify({
            'message': 'Cache cleared successfully'
        })
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500


@app.route('/api/analyze-detailed', methods=['POST'])
def analyze_detailed():
    """Detailed analysis with all algorithm results"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        url = URLValidator.sanitize_url(url)
        
        if not URLValidator.is_valid_url(url):
            return jsonify({'error': 'Invalid URL format'}), 400
        
        # Get standard analysis
        result = detector.analyze_url(url)
        
        # Add detailed algorithm information
        result['algorithm_details'] = {
            'blacklist_lookup': 'O(1) Hash Set',
            'keyword_search': 'Aho-Corasick O(n+m+z)',
            'pattern_matching': 'KMP O(n+m)',
            'typosquatting': 'Levenshtein Distance O(m*n)',
            'total_checks': 13
        }
        
        # Add URL components
        result['url_components'] = URLValidator.extract_components(url)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _save_to_history(result: dict):
    """Save detection result to history"""
    try:
        history = []
        
        # Create logs directory if it doesn't exist
        Config.LOGS_DIR.mkdir(exist_ok=True)
        
        if history_file.exists():
            try:
                with open(history_file, 'r') as f:
                    content = f.read().strip()
                    if content:  # Only load if file has content
                        history = json.loads(content)
            except (json.JSONDecodeError, Exception):
                # If there's an error reading the file, start with empty history
                history = []
        
        # Keep only essential info for history
        history_entry = {
            'url': result['url'],
            'timestamp': result['timestamp'],
            'risk_level': result['risk_level'],
            'total_score': result['total_score'],
            'threat_count': len(result['threats_detected'])
        }
        
        history.append(history_entry)
        
        # Keep only last 1000 entries
        history = history[-1000:]
        
        with open(history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    except Exception as e:
        # Log error to console but don't fail the request
        print(f"Warning: Could not save to history: {e}")

# Error handlers
@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  PHISHING URL DETECTOR API")
    print("="*60)
    print(f"Server starting on {Config.FLASK_HOST}:{Config.FLASK_PORT}")
    print(f"Blacklist entries: {detector.blacklist_hashset.size()}")
    print(f"Whitelist entries: {detector.whitelist.size()}")
    print(f"Debug mode: {Config.DEBUG}")
    print("="*60 + "\n")
    
    app.run(
        host=Config.FLASK_HOST,
        port=Config.FLASK_PORT,
        debug=Config.DEBUG
    )