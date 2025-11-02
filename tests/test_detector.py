import pytest
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'backend'))

from detector import PhishingDetector
from algorithms import KMPAlgorithm, LevenshteinDistance
from data_structures import Trie, HashSet, AhoCorasick


class TestPhishingDetector:
    """Test cases for PhishingDetector"""
    
    @pytest.fixture
    def detector(self):
        return PhishingDetector()
    
    def test_safe_url(self, detector):
        """Test detection of safe URL"""
        result = detector.analyze_url('https://www.google.com')
        assert result['risk_level'] == 'safe'
        assert result['total_score'] < 5
    
    def test_ip_address_detection(self, detector):
        """Test IP address in URL detection"""
        result = detector.analyze_url('http://192.168.1.1/login')
        threats = [t['type'] for t in result['threats_detected']]
        assert 'ip_address' in threats
    
    def test_suspicious_tld(self, detector):
        """Test suspicious TLD detection"""
        result = detector.analyze_url('http://phishing-site.tk')
        threats = [t['type'] for t in result['threats_detected']]
        assert 'suspicious_tld' in threats or result['total_score'] > 0
    
    def test_excessive_length(self, detector):
        """Test excessive URL length detection"""
        long_url = 'http://example.com/' + 'a' * 100
        result = detector.analyze_url(long_url)
        assert result['details']['url_length'] > 100
    
    def test_suspicious_keywords(self, detector):
        """Test keyword detection"""
        result = detector.analyze_url('http://secure-login-verify-account.com')
        threats = [t['type'] for t in result['threats_detected']]
        assert 'suspicious_keywords' in threats
    
    def test_punycode_detection(self, detector):
        """Test punycode detection"""
        result = detector.analyze_url('http://xn--e1afmkfd.xn--p1ai')
        threats = [t['type'] for t in result['threats_detected']]
        assert 'punycode' in threats
    
    def test_typosquatting(self, detector):
        """Test typosquatting detection"""
        result = detector.analyze_url('http://gooogle.com')
        threats = [t['type'] for t in result['threats_detected']]
        assert 'typosquatting' in threats
    
    def test_cache_functionality(self, detector):
        """Test LRU cache"""
        url = 'https://www.example.com'
        result1 = detector.analyze_url(url)
        result2 = detector.analyze_url(url)
        
        assert detector.stats['cache_hits'] > 0
        assert result1['url'] == result2['url']
    
    def test_blacklist_addition(self, detector):
        """Test adding to blacklist"""
        test_domain = 'test-phishing-site.com'
        detector.add_to_blacklist(test_domain)
        assert detector.blacklist_hashset.contains(test_domain)


class TestAlgorithms:
    """Test cases for string matching algorithms"""
    
    def test_kmp_search(self):
        """Test KMP algorithm"""
        text = "this is a test string for testing"
        pattern = "test"
        positions = KMPAlgorithm.search(text, pattern)
        assert len(positions) == 2
        assert positions[0] == 10
    
    def test_kmp_no_match(self):
        """Test KMP with no matches"""
        text = "hello world"
        pattern = "xyz"
        positions = KMPAlgorithm.search(text, pattern)
        assert len(positions) == 0
    
    def test_levenshtein_distance(self):
        """Test Levenshtein distance calculation"""
        distance = LevenshteinDistance.calculate("kitten", "sitting")
        assert distance == 3
    
    def test_levenshtein_similar(self):
        """Test similarity check"""
        assert LevenshteinDistance.is_similar("google", "gooogle", threshold=2)
        assert not LevenshteinDistance.is_similar("google", "facebook", threshold=2)


class TestDataStructures:
    """Test cases for data structures"""
    
    def test_trie_insert_search(self):
        """Test Trie insertion and search"""
        trie = Trie()
        trie.insert("hello")
        trie.insert("world")
        
        assert trie.search("hello")
        assert trie.search("world")
        assert not trie.search("test")
    
    def test_trie_prefix(self):
        """Test Trie prefix search"""
        trie = Trie()
        trie.insert("hello")
        trie.insert("help")
        
        assert trie.starts_with("hel")
        assert not trie.starts_with("wor")
    
    def test_hashset_operations(self):
        """Test HashSet operations"""
        hashset = HashSet()
        hashset.add("test")
        
        assert hashset.contains("test")
        assert hashset.size() == 1
        
        hashset.remove("test")
        assert not hashset.contains("test")
    
    def test_aho_corasick_multi_pattern(self):
        """Test Aho-Corasick multi-pattern search"""
        ac = AhoCorasick()
        ac.add_pattern("login")
        ac.add_pattern("verify")
        ac.add_pattern("secure")
        ac.build()
        
        text = "secure-login-verify-account"
        matches = ac.search(text)
        
        assert len(matches) == 3
        found_patterns = [match[2] for match in matches]
        assert "login" in found_patterns
        assert "verify" in found_patterns
        assert "secure" in found_patterns


class TestIntegration:
    """Integration tests"""
    
    @pytest.fixture
    def detector(self):
        return PhishingDetector()
    
    def test_phishing_url_high_score(self, detector):
        """Test that obvious phishing URL gets high score"""
        url = "http://192.168.1.1/secure-login-verify-paypal-account.tk"
        result = detector.analyze_url(url)
        assert result['total_score'] >= 5
        assert result['risk_level'] in ['suspicious', 'dangerous']
    
    def test_legitimate_url_low_score(self, detector):
        """Test that legitimate URL gets low score"""
        url = "https://www.github.com"
        result = detector.analyze_url(url)
        assert result['total_score'] < 3
        assert result['risk_level'] == 'safe'
    
    def test_multiple_threats(self, detector):
        """Test URL with multiple threat indicators"""
        url = "http://secure-verify-login.tk/update?confirm=true"
        result = detector.analyze_url(url)
        assert len(result['threats_detected']) >= 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])