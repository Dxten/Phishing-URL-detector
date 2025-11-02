import re
import tldextract
from urllib.parse import urlparse
from typing import Dict, List, Tuple
from datetime import datetime
import json

from data_structures import Trie, HashSet, AhoCorasick, BloomFilter, LRUCache
from algorithms import StringMatcher, LevenshteinDistance, RegexMatcher
from config import Config


class PhishingDetector:
    """Core phishing detection engine with multiple detection methods"""
    
    def __init__(self):
        # Initialize data structures
        self.blacklist_hashset = HashSet()
        self.blacklist_trie = Trie()
        self.blacklist_bloom = BloomFilter(size=1000000, hash_count=7)
        self.whitelist = HashSet()
        
        # Keyword matching
        self.keyword_matcher = AhoCorasick()
        self.string_matcher = StringMatcher(algorithm='kmp')
        
        # Cache for recent results
        self.cache = LRUCache(capacity=1000)
        
        # Load datasets
        self._load_blacklist()
        self._load_whitelist()
        self._load_keywords()
        
        # Statistics
        self.stats = {
            'total_analyzed': 0,
            'phishing_detected': 0,
            'safe_urls': 0,
            'suspicious_urls': 0,
            'cache_hits': 0
        }
    
    def _load_blacklist(self):
        """Load phishing URLs from blacklist file"""
        try:
            if Config.PHISHING_URLS_FILE.exists():
                with open(Config.PHISHING_URLS_FILE, 'r') as f:
                    for line in f:
                        url = line.strip()
                        if url and not url.startswith('#'):
                            domain = self._extract_domain(url)
                            self.blacklist_hashset.add(domain)
                            self.blacklist_trie.insert(domain)
                            self.blacklist_bloom.add(domain)
                print(f"✓ Loaded {self.blacklist_hashset.size()} blacklist entries")
        except Exception as e:
            print(f"Warning: Could not load blacklist: {e}")
    
    def _load_whitelist(self):
        """Load legitimate URLs from whitelist file"""
        try:
            if Config.LEGITIMATE_URLS_FILE.exists():
                with open(Config.LEGITIMATE_URLS_FILE, 'r') as f:
                    urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                    self.whitelist.add_bulk(urls)
                print(f"✓ Loaded {self.whitelist.size()} whitelist entries")
        except Exception as e:
            print(f"Warning: Could not load whitelist: {e}")
    
    def _load_keywords(self):
        """Load suspicious keywords for pattern matching"""
        try:
            keywords = Config.get_suspicious_keywords()
            for keyword in keywords:
                self.keyword_matcher.add_pattern(keyword)
            self.keyword_matcher.build()
            print(f"✓ Loaded {len(keywords)} suspicious keywords")
        except Exception as e:
            print(f"Warning: Could not load keywords: {e}")
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            return domain.lower()
        except:
            return url.lower()
    
    def analyze_url(self, url: str) -> Dict:
        """Main analysis function - returns detailed results"""
        # Check cache first
        cached_result = self.cache.get(url)
        if cached_result:
            self.stats['cache_hits'] += 1
            return cached_result
        
        # Initialize result
        result = {
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'is_phishing': False,
            'risk_level': 'safe',
            'confidence': 0.0,
            'total_score': 0,
            'threats_detected': [],
            'details': {}
        }
        
        try:
            # Parse URL
            parsed = urlparse(url)
            domain = self._extract_domain(url)
            
            # Run all detection methods
            score = 0
            threats = []
            
            # 1. Blacklist check
            blacklist_result = self._check_blacklist(domain)
            if blacklist_result['found']:
                score += Config.WEIGHTS['blacklist_match']
                threats.append({
                    'type': 'blacklist_match',
                    'severity': 'critical',
                    'description': 'Domain found in known phishing blacklist',
                    'score': Config.WEIGHTS['blacklist_match']
                })
            
            # 2. Whitelist check (reduces score)
            if self.whitelist.contains(domain):
                result['details']['whitelist'] = True
                score = max(0, score - 5)
            
            # 3. IP address check
            ip_result = self._check_ip_address(parsed.netloc)
            if ip_result['has_ip']:
                score += Config.WEIGHTS['ip_address']
                threats.append({
                    'type': 'ip_address',
                    'severity': 'high',
                    'description': f'Uses IP address instead of domain: {ip_result["ip"]}',
                    'score': Config.WEIGHTS['ip_address']
                })
            
            # 4. Suspicious TLD
            tld_result = self._check_suspicious_tld(domain)
            if tld_result['is_suspicious']:
                score += Config.WEIGHTS['suspicious_tld']
                threats.append({
                    'type': 'suspicious_tld',
                    'severity': 'medium',
                    'description': f'Suspicious TLD: {tld_result["tld"]}',
                    'score': Config.WEIGHTS['suspicious_tld']
                })
            
            # 5. URL length
            length_result = self._check_url_length(url)
            if length_result['excessive']:
                score += Config.WEIGHTS['excessive_length']
                threats.append({
                    'type': 'excessive_length',
                    'severity': 'medium',
                    'description': f'Unusually long URL: {length_result["length"]} chars',
                    'score': Config.WEIGHTS['excessive_length']
                })
            
            # 6. Suspicious keywords
            keyword_result = self._check_keywords(url)
            if keyword_result['found']:
                score += Config.WEIGHTS['suspicious_keywords']
                threats.append({
                    'type': 'suspicious_keywords',
                    'severity': 'high',
                    'description': f'Suspicious keywords: {", ".join(keyword_result["keywords"][:3])}',
                    'score': Config.WEIGHTS['suspicious_keywords'],
                    'keywords': keyword_result['keywords']
                })
            
            # 7. URL shortener
            shortener_result = self._check_url_shortener(domain)
            if shortener_result['is_shortener']:
                score += Config.WEIGHTS['url_shortener']
                threats.append({
                    'type': 'url_shortener',
                    'severity': 'medium',
                    'description': 'Uses URL shortening service',
                    'score': Config.WEIGHTS['url_shortener']
                })
            
            # 8. Punycode (IDN homograph attack)
            punycode_result = self._check_punycode(url)
            if punycode_result['has_punycode']:
                score += Config.WEIGHTS['punycode']
                threats.append({
                    'type': 'punycode',
                    'severity': 'high',
                    'description': 'Contains punycode (possible homograph attack)',
                    'score': Config.WEIGHTS['punycode']
                })
            
            # 9. Excessive subdomains
            subdomain_result = self._check_subdomains(parsed.netloc)
            if subdomain_result['excessive']:
                score += Config.WEIGHTS['excessive_subdomains']
                threats.append({
                    'type': 'excessive_subdomains',
                    'severity': 'medium',
                    'description': f'{subdomain_result["count"]} subdomains detected',
                    'score': Config.WEIGHTS['excessive_subdomains']
                })
            
            # 10. Suspicious port
            port_result = self._check_suspicious_port(parsed.port)
            if port_result['is_suspicious']:
                score += Config.WEIGHTS['suspicious_port']
                threats.append({
                    'type': 'suspicious_port',
                    'severity': 'low',
                    'description': f'Non-standard port: {port_result["port"]}',
                    'score': Config.WEIGHTS['suspicious_port']
                })
            
            # 11. Typosquatting
            typo_result = self._check_typosquatting(domain)
            if typo_result['is_typosquatting']:
                score += Config.WEIGHTS['typosquatting']
                threats.append({
                    'type': 'typosquatting',
                    'severity': 'high',
                    'description': f'Possible typosquatting of: {typo_result["similar_to"]}',
                    'score': Config.WEIGHTS['typosquatting']
                })
            
            # 12. Suspicious patterns
            pattern_result = self._check_patterns(url)
            if pattern_result['found']:
                score += Config.WEIGHTS['suspicious_patterns']
                threats.append({
                    'type': 'suspicious_patterns',
                    'severity': 'medium',
                    'description': f'Suspicious patterns: {", ".join(pattern_result["patterns"])}',
                    'score': Config.WEIGHTS['suspicious_patterns']
                })
            
            # 13. Special characters
            special_char_result = self._check_special_chars(url)
            if special_char_result['excessive']:
                score += Config.WEIGHTS['excessive_special_chars']
                threats.append({
                    'type': 'excessive_special_chars',
                    'severity': 'low',
                    'description': f'Excessive special characters: {special_char_result["count"]}',
                    'score': Config.WEIGHTS['excessive_special_chars']
                })
            
            # Calculate final results
            result['total_score'] = score
            result['threats_detected'] = threats
            
            # Determine risk level
            if score >= Config.PHISHING_THRESHOLD:
                result['is_phishing'] = True
                result['risk_level'] = 'dangerous'
                result['confidence'] = min(0.95, 0.5 + (score / 20))
                self.stats['phishing_detected'] += 1
            elif score >= Config.SUSPICIOUS_THRESHOLD:
                result['risk_level'] = 'suspicious'
                result['confidence'] = 0.3 + (score / 30)
                self.stats['suspicious_urls'] += 1
            else:
                result['risk_level'] = 'safe'
                result['confidence'] = max(0.05, 1.0 - (score / 10))
                self.stats['safe_urls'] += 1
            
            # Add detailed analysis
            result['details'] = {
                'domain': domain,
                'scheme': parsed.scheme,
                'has_path': bool(parsed.path and parsed.path != '/'),
                'has_query': bool(parsed.query),
                'has_fragment': bool(parsed.fragment),
                'url_length': len(url),
                'threat_count': len(threats)
            }
            
            self.stats['total_analyzed'] += 1
            
            # Cache result
            self.cache.put(url, result)
            
        except Exception as e:
            result['error'] = str(e)
            result['risk_level'] = 'error'
        
        return result
    
    def _check_blacklist(self, domain: str) -> Dict:
        """Check if domain is in blacklist using multiple data structures"""
        # Quick bloom filter check (may have false positives)
        bloom_match = self.blacklist_bloom.contains(domain)
        
        # Confirm with hash set (100% accurate)
        hashset_match = self.blacklist_hashset.contains(domain)
        
        # Trie check for prefix matching
        trie_match = self.blacklist_trie.search(domain)
        
        return {
            'found': hashset_match,
            'bloom_match': bloom_match,
            'trie_match': trie_match
        }
    
    def _check_ip_address(self, netloc: str) -> Dict:
        """Check if URL uses IP address instead of domain"""
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        match = re.search(ip_pattern, netloc)
        return {
            'has_ip': bool(match),
            'ip': match.group(0) if match else None
        }
    
    def _check_suspicious_tld(self, domain: str) -> Dict:
        """Check for suspicious top-level domains"""
        try:
            extracted = tldextract.extract(domain)
            tld = extracted.suffix.lower()
            is_suspicious = tld in Config.SUSPICIOUS_TLDS
            return {
                'is_suspicious': is_suspicious,
                'tld': tld
            }
        except:
            return {'is_suspicious': False, 'tld': None}
    
    def _check_url_length(self, url: str) -> Dict:
        """Check if URL is excessively long"""
        length = len(url)
        return {
            'excessive': length > Config.MAX_URL_LENGTH,
            'length': length
        }
    
    def _check_keywords(self, url: str) -> Dict:
        """Check for suspicious keywords using Aho-Corasick"""
        matches = self.keyword_matcher.search(url.lower())
        keywords_found = list(set([match[2] for match in matches]))
        return {
            'found': len(keywords_found) > 0,
            'keywords': keywords_found,
            'count': len(keywords_found)
        }
    
    def _check_url_shortener(self, domain: str) -> Dict:
        """Check if domain is a known URL shortener"""
        is_shortener = domain in Config.URL_SHORTENERS
        return {'is_shortener': is_shortener}
    
    def _check_punycode(self, url: str) -> Dict:
        """Check for punycode (IDN homograph attacks)"""
        has_punycode = 'xn--' in url.lower()
        return {'has_punycode': has_punycode}
    
    def _check_subdomains(self, netloc: str) -> Dict:
        """Check for excessive subdomains"""
        # Remove port if present
        netloc = netloc.split(':')[0]
        subdomain_count = netloc.count('.')
        return {
            'excessive': subdomain_count > Config.MAX_SUBDOMAINS,
            'count': subdomain_count
        }
    
    def _check_suspicious_port(self, port) -> Dict:
        """Check for non-standard ports"""
        if port and port not in [80, 443, 8080, 8443]:
            return {'is_suspicious': True, 'port': port}
        return {'is_suspicious': False, 'port': port}
    
    def _check_typosquatting(self, domain: str) -> Dict:
        """Check for typosquatting using Levenshtein distance"""
        for legit_domain in Config.LEGITIMATE_DOMAINS:
            if LevenshteinDistance.is_similar(domain, legit_domain, threshold=2):
                if domain != legit_domain:
                    return {
                        'is_typosquatting': True,
                        'similar_to': legit_domain
                    }
        return {'is_typosquatting': False, 'similar_to': None}
    
    def _check_patterns(self, url: str) -> Dict:
        """Check for suspicious patterns using regex"""
        patterns_found = []
        
        if re.search(r'@', url):
            patterns_found.append('@_symbol')
        
        if re.search(r'-{2,}', url):
            patterns_found.append('multiple_hyphens')
        
        if re.search(r'%[0-9a-f]{2}', url.lower()):
            patterns_found.append('hex_encoding')
        
        if re.search(r'//', url[8:]):  # Skip protocol
            patterns_found.append('double_slash')
        
        return {
            'found': len(patterns_found) > 0,
            'patterns': patterns_found
        }
    
    def _check_special_chars(self, url: str) -> Dict:
        """Check for excessive special characters"""
        special_chars = re.findall(r'[^a-zA-Z0-9./:\-?=&]', url)
        count = len(special_chars)
        return {
            'excessive': count > 10,
            'count': count
        }
    
    def get_statistics(self) -> Dict:
        """Return detection statistics"""
        return self.stats.copy()
    
    def add_to_blacklist(self, domain: str):
        """Add domain to blacklist"""
        self.blacklist_hashset.add(domain)
        self.blacklist_trie.insert(domain)
        self.blacklist_bloom.add(domain)
    
    def clear_cache(self):
        """Clear the LRU cache"""
        self.cache.clear()
        self.stats['cache_hits'] = 0