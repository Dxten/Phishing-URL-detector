from typing import List, Tuple
import re

class KMPAlgorithm:
    """Knuth-Morris-Pratt algorithm for pattern matching - O(n + m) time"""
    
    @staticmethod
    def compute_lps(pattern: str) -> List[int]:
        """Compute Longest Proper Prefix which is also Suffix array"""
        m = len(pattern)
        lps = [0] * m
        length = 0
        i = 1
        
        while i < m:
            if pattern[i] == pattern[length]:
                length += 1
                lps[i] = length
                i += 1
            else:
                if length != 0:
                    length = lps[length - 1]
                else:
                    lps[i] = 0
                    i += 1
        
        return lps
    
    @staticmethod
    def search(text: str, pattern: str) -> List[int]:
        """Search for pattern in text - returns list of starting positions"""
        text = text.lower()
        pattern = pattern.lower()
        
        n = len(text)
        m = len(pattern)
        
        if m == 0 or m > n:
            return []
        
        lps = KMPAlgorithm.compute_lps(pattern)
        positions = []
        
        i = 0  # text index
        j = 0  # pattern index
        
        while i < n:
            if text[i] == pattern[j]:
                i += 1
                j += 1
            
            if j == m:
                positions.append(i - j)
                j = lps[j - 1]
            elif i < n and text[i] != pattern[j]:
                if j != 0:
                    j = lps[j - 1]
                else:
                    i += 1
        
        return positions


class RabinKarpAlgorithm:
    """Rabin-Karp algorithm for pattern matching using rolling hash - O(n + m) average"""
    
    def __init__(self, prime: int = 101):
        self.prime = prime
        self.base = 256
    
    def _hash(self, s: str, length: int) -> int:
        """Calculate hash value for string of given length"""
        h = 0
        for i in range(length):
            h = (h * self.base + ord(s[i])) % self.prime
        return h
    
    def _recalculate_hash(self, text: str, old_index: int, new_index: int, 
                          old_hash: int, pattern_len: int) -> int:
        """Recalculate hash by removing old char and adding new char"""
        new_hash = (old_hash - ord(text[old_index]) * pow(self.base, pattern_len - 1, self.prime)) % self.prime
        new_hash = (new_hash * self.base + ord(text[new_index])) % self.prime
        return new_hash
    
    def search(self, text: str, pattern: str) -> List[int]:
        """Search for pattern in text using rolling hash"""
        text = text.lower()
        pattern = pattern.lower()
        
        n = len(text)
        m = len(pattern)
        
        if m > n or m == 0:
            return []
        
        pattern_hash = self._hash(pattern, m)
        text_hash = self._hash(text, m)
        positions = []
        
        for i in range(n - m + 1):
            if pattern_hash == text_hash:
                # Hash match - verify actual string
                if text[i:i + m] == pattern:
                    positions.append(i)
            
            if i < n - m:
                text_hash = self._recalculate_hash(text, i, i + m, text_hash, m)
        
        return positions


class BoyerMooreAlgorithm:
    """Boyer-Moore algorithm for efficient pattern matching - O(n/m) best case"""
    
    @staticmethod
    def _bad_character_table(pattern: str) -> dict:
        """Build bad character heuristic table"""
        table = {}
        m = len(pattern)
        
        for i in range(m - 1):
            table[pattern[i]] = m - 1 - i
        
        return table
    
    @staticmethod
    def search(text: str, pattern: str) -> List[int]:
        """Search for pattern using Boyer-Moore algorithm"""
        text = text.lower()
        pattern = pattern.lower()
        
        n = len(text)
        m = len(pattern)
        
        if m > n or m == 0:
            return []
        
        bad_char = BoyerMooreAlgorithm._bad_character_table(pattern)
        positions = []
        
        i = 0
        while i <= n - m:
            j = m - 1
            
            while j >= 0 and pattern[j] == text[i + j]:
                j -= 1
            
            if j < 0:
                positions.append(i)
                i += 1
            else:
                shift = bad_char.get(text[i + j], m)
                i += max(1, j - shift)
        
        return positions


class LevenshteinDistance:
    """Calculate edit distance for typosquatting detection"""
    
    @staticmethod
    def calculate(s1: str, s2: str) -> int:
        """Calculate minimum edit distance between two strings - O(m*n)"""
        s1 = s1.lower()
        s2 = s2.lower()
        
        m, n = len(s1), len(s2)
        
        # Create DP table
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        # Initialize base cases
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        
        # Fill DP table
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i - 1] == s2[j - 1]:
                    dp[i][j] = dp[i - 1][j - 1]
                else:
                    dp[i][j] = 1 + min(
                        dp[i - 1][j],      # deletion
                        dp[i][j - 1],      # insertion
                        dp[i - 1][j - 1]   # substitution
                    )
        
        return dp[m][n]
    
    @staticmethod
    def is_similar(s1: str, s2: str, threshold: int = 2) -> bool:
        """Check if strings are similar within threshold"""
        distance = LevenshteinDistance.calculate(s1, s2)
        return distance <= threshold


class StringMatcher:
    """Unified interface for different string matching algorithms"""
    
    def __init__(self, algorithm: str = 'kmp'):
        """
        Initialize with chosen algorithm
        Options: 'kmp', 'rabin-karp', 'boyer-moore'
        """
        self.algorithm = algorithm.lower()
        self.kmp = KMPAlgorithm()
        self.rabin_karp = RabinKarpAlgorithm()
        self.boyer_moore = BoyerMooreAlgorithm()
    
    def search(self, text: str, pattern: str) -> List[int]:
        """Search for pattern using selected algorithm"""
        if self.algorithm == 'kmp':
            return self.kmp.search(text, pattern)
        elif self.algorithm == 'rabin-karp':
            return self.rabin_karp.search(text, pattern)
        elif self.algorithm == 'boyer-moore':
            return self.boyer_moore.search(text, pattern)
        else:
            # Fallback to Python's built-in
            return self._builtin_search(text, pattern)
    
    def _builtin_search(self, text: str, pattern: str) -> List[int]:
        """Fallback using Python's built-in string search"""
        positions = []
        text = text.lower()
        pattern = pattern.lower()
        start = 0
        
        while True:
            pos = text.find(pattern, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        return positions
    
    def search_multiple(self, text: str, patterns: List[str]) -> dict:
        """Search for multiple patterns - returns dict of pattern: positions"""
        results = {}
        for pattern in patterns:
            positions = self.search(text, pattern)
            if positions:
                results[pattern] = positions
        return results


class RegexMatcher:
    """Regex-based pattern matching for complex patterns"""
    
    # Common phishing URL patterns
    PATTERNS = {
        'ip_address': r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
        'excessive_subdomain': r'([a-z0-9-]+\.){4,}',
        'suspicious_port': r':[0-9]{2,5}(?:/|$)',
        'punycode': r'xn--',
        'at_symbol': r'@',
        'double_slash': r'//.+//',
        'excessive_hyphens': r'-{2,}',
        'suspicious_query': r'\?.*(?:login|password|credential|verify|secure|account)',
        'hex_encoding': r'%[0-9a-f]{2}',
        'data_uri': r'data:text/html',
    }
    
    @staticmethod
    def match_pattern(text: str, pattern_name: str) -> bool:
        """Check if text matches a specific pattern"""
        if pattern_name not in RegexMatcher.PATTERNS:
            return False
        
        pattern = RegexMatcher.PATTERNS[pattern_name]
        return bool(re.search(pattern, text.lower()))
    
    @staticmethod
    def find_all_matches(text: str, pattern_name: str) -> List[str]:
        """Find all matches for a pattern"""
        if pattern_name not in RegexMatcher.PATTERNS:
            return []
        
        pattern = RegexMatcher.PATTERNS[pattern_name]
        return re.findall(pattern, text.lower())
    
    @staticmethod
    def check_all_patterns(text: str) -> dict:
        """Check text against all patterns"""
        results = {}
        for name, pattern in RegexMatcher.PATTERNS.items():
            matches = re.findall(pattern, text.lower())
            if matches:
                results[name] = matches
        return results