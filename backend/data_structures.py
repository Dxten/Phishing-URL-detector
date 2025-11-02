from typing import List, Set, Dict, Optional
from collections import defaultdict
import hashlib

class TrieNode:
    """Node for Trie data structure"""
    def __init__(self):
        self.children = {}
        self.is_end_of_word = False
        self.data = None  # type: Optional[dict]

class Trie:
    """Trie (Prefix Tree) for efficient domain matching - O(m) lookup where m is string length"""
    
    def __init__(self):
        self.root = TrieNode()
        self.size = 0
    
    def insert(self, word: str, data: Optional[dict] = None):
        """Insert a word into the trie"""
        node = self.root
        for char in word.lower():
            if char not in node.children:
                node.children[char] = TrieNode()
            node = node.children[char]
        
        if not node.is_end_of_word:
            self.size += 1
        node.is_end_of_word = True
        node.data = data
    
    def search(self, word: str) -> bool:
        """Search for exact word match - O(m) time"""
        node = self._find_node(word)
        return node is not None and node.is_end_of_word
    
    def starts_with(self, prefix: str) -> bool:
        """Check if any word starts with prefix"""
        return self._find_node(prefix) is not None
    
    def _find_node(self, word: str) -> Optional[TrieNode]:
        """Helper to find node for given word"""
        node = self.root
        for char in word.lower():
            if char not in node.children:
                return None
            node = node.children[char]
        return node
    
    def get_all_words(self, prefix: str = '') -> List[str]:
        """Get all words with given prefix"""
        node = self._find_node(prefix)
        if not node:
            return []
        
        words = []
        self._collect_words(node, prefix, words)
        return words
    
    def _collect_words(self, node: TrieNode, prefix: str, words: List[str]):
        """Recursively collect all words from node"""
        if node.is_end_of_word:
            words.append(prefix)
        
        for char, child_node in node.children.items():
            self._collect_words(child_node, prefix + char, words)


class BloomFilter:
    """Space-efficient probabilistic data structure for blacklist checking
    False positives possible but false negatives never occur"""
    
    def __init__(self, size: int = 1000000, hash_count: int = 7):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [False] * size
        self.item_count = 0
    
    def _hash(self, item: str, seed: int) -> int:
        """Generate hash with seed"""
        hash_val = hashlib.md5(f"{item}{seed}".encode()).hexdigest()
        return int(hash_val, 16) % self.size
    
    def add(self, item: str):
        """Add item to bloom filter"""
        for i in range(self.hash_count):
            index = self._hash(item.lower(), i)
            self.bit_array[index] = True
        self.item_count += 1
    
    def contains(self, item: str) -> bool:
        """Check if item might be in set - O(k) where k is hash_count"""
        for i in range(self.hash_count):
            index = self._hash(item.lower(), i)
            if not self.bit_array[index]:
                return False
        return True
    
    def estimated_false_positive_rate(self) -> float:
        """Calculate estimated false positive probability"""
        if self.item_count == 0:
            return 0.0
        # FPR = (1 - e^(-k*n/m))^k
        import math
        k = self.hash_count
        n = self.item_count
        m = self.size
        return (1 - math.exp(-k * n / m)) ** k


class AhoCorasick:
    """Simplified pattern matching - O(n*m) but more reliable"""
    
    def __init__(self):
        self.patterns = []
        self._built = True
    
    def add_pattern(self, pattern: str):
        """Add pattern to matcher"""
        self.patterns.append(pattern.lower())
    
    def build(self):
        """Build the matcher (no-op in simplified version)"""
        pass
    
    def search(self, text: str) -> List[tuple]:
        """Search for all patterns in text - returns list of (pattern_idx, position, pattern)"""
        matches = []
        text = text.lower()
        
        for idx, pattern in enumerate(self.patterns):
            start = 0
            while True:
                pos = text.find(pattern, start)
                if pos == -1:
                    break
                matches.append((idx, pos, pattern))
                start = pos + 1
        
        # Sort by position
        matches.sort(key=lambda x: x[1])
        return matches


class HashSet:
    """Optimized hash set for O(1) lookups"""
    
    def __init__(self, initial_data: Optional[List[str]] = None):
        self.data = set()
        if initial_data:
            self.add_bulk(initial_data)
    
    def add(self, item: str):
        """Add item - O(1) average"""
        self.data.add(item.lower())
    
    def add_bulk(self, items: List[str]):
        """Add multiple items efficiently"""
        self.data.update(item.lower() for item in items)
    
    def contains(self, item: str) -> bool:
        """Check if item exists - O(1) average"""
        return item.lower() in self.data
    
    def remove(self, item: str):
        """Remove item if exists"""
        self.data.discard(item.lower())
    
    def size(self) -> int:
        """Return number of items"""
        return len(self.data)
    
    def clear(self):
        """Clear all items"""
        self.data.clear()


class LRUCache:
    """LRU Cache for caching recent URL analysis results"""
    
    def __init__(self, capacity: int = 1000):
        self.capacity = capacity
        self.cache = {}
        self.order = []
    
    def get(self, key: str):
        """Get item from cache"""
        if key in self.cache:
            # Move to end (most recent)
            self.order.remove(key)
            self.order.append(key)
            return self.cache[key]
        return None
    
    def put(self, key: str, value):
        """Put item in cache"""
        if key in self.cache:
            self.order.remove(key)
        elif len(self.cache) >= self.capacity:
            # Remove oldest
            oldest = self.order.pop(0)
            del self.cache[oldest]
        
        self.cache[key] = value
        self.order.append(key)
    
    def clear(self):
        """Clear cache"""
        self.cache.clear()
        self.order.clear()