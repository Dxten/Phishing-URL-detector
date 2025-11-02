import os
from pathlib import Path

class Config:
    """Configuration settings for Phishing URL Detector"""
    
    # Base directories
    BASE_DIR = Path(__file__).parent.parent
    BACKEND_DIR = BASE_DIR / 'backend'
    DATASETS_DIR = BASE_DIR / 'datasets'
    LOGS_DIR = BASE_DIR / 'logs'
    
    # Dataset files
    PHISHING_URLS_FILE = DATASETS_DIR / 'phishing_urls.txt'
    LEGITIMATE_URLS_FILE = DATASETS_DIR / 'legitimate_urls.txt'
    KEYWORDS_FILE = DATASETS_DIR / 'keywords.json'
    
    # Log files
    DETECTION_LOG = LOGS_DIR / 'detection_history.json'
    
    # API Configuration
    FLASK_HOST = os.getenv('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.getenv('FLASK_PORT', 5000))
    DEBUG = os.getenv('DEBUG', 'False') == 'True'
    
    # External APIs for blacklist updates
    PHISHTANK_API = 'http://data.phishtank.com/data/online-valid.json'
    OPENPHISH_API = 'https://openphish.com/feed.txt'
    
    # Update intervals (in hours)
    BLACKLIST_UPDATE_INTERVAL = 24
    
    # Detection thresholds
    PHISHING_THRESHOLD = 5  # Score >= 5 is phishing
    SUSPICIOUS_THRESHOLD = 3  # Score 3-4 is suspicious
    
    # Scoring weights
    WEIGHTS = {
        'blacklist_match': 10,
        'ip_address': 3,
        'suspicious_tld': 2,
        'excessive_length': 2,
        'suspicious_keywords': 2,
        'url_shortener': 2,
        'suspicious_port': 1,
        'punycode': 2,
        'excessive_subdomains': 2,
        'suspicious_patterns': 1,
        'typosquatting': 3,
        'suspicious_path': 1,
        'excessive_special_chars': 1,
    }
    
    # Suspicious TLDs
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
        'click', 'link', 'zip', 'review', 'country', 'stream',
        'download', 'loan', 'racing', 'accountant', 'science'
    }
    
    # URL shorteners
    URL_SHORTENERS = {
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
        'is.gd', 'buff.ly', 'adf.ly', 'bit.do', 'short.link',
        'tiny.cc', 'url.ie', 'v.gd', 'x.co', 'budurl.com'
    }
    
    # Suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        'login', 'verify', 'account', 'secure', 'banking',
        'update', 'confirm', 'suspended', 'locked', 'unusual',
        'signin', 'password', 'credential', 'security', 'billing',
        'payment', 'paypal', 'ebay', 'amazon', 'apple',
        'microsoft', 'google', 'facebook', 'twitter', 'netflix',
        'wallet', 'crypto', 'blockchain', 'prize', 'winner',
        'urgent', 'immediate', 'action', 'required', 'expire'
    ]
    
    # Popular legitimate domains (for typosquatting detection)
    LEGITIMATE_DOMAINS = {
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com',
        'yahoo.com', 'twitter.com', 'instagram.com', 'linkedin.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'reddit.com',
        'ebay.com', 'paypal.com', 'github.com', 'stackoverflow.com'
    }
    
    # Maximum URL length (normal URLs are usually < 100 chars)
    MAX_URL_LENGTH = 75
    
    # Maximum number of subdomains
    MAX_SUBDOMAINS = 3
    
    # Rate limiting
    MAX_REQUESTS_PER_MINUTE = 100
    
    @classmethod
    def ensure_directories(cls):
        """Ensure all required directories exist"""
        cls.DATASETS_DIR.mkdir(exist_ok=True)
        cls.LOGS_DIR.mkdir(exist_ok=True)
    
    @classmethod
    def get_suspicious_keywords(cls):
        """Return list of suspicious keywords"""
        return cls.SUSPICIOUS_KEYWORDS
    
    @classmethod
    def get_scoring_weights(cls):
        """Return scoring weights dictionary"""
        return cls.WEIGHTS