from data_structures import Trie, HashSet, AhoCorasick, BloomFilter, LRUCache
from config import Config

print("Starting debug test...")

# Initialize data structures
print("1. Initializing data structures...")
blacklist_hashset = HashSet()
blacklist_trie = Trie()
blacklist_bloom = BloomFilter(size=1000000, hash_count=7)
whitelist = HashSet()

# Keyword matching
print("2. Initializing keyword matcher...")
keyword_matcher = AhoCorasick()
string_matcher = None  # StringMatcher(algorithm='kmp')

# Cache for recent results
print("3. Initializing cache...")
cache = LRUCache(capacity=1000)

print("4. Loading keywords...")
try:
    keywords = Config.get_suspicious_keywords()
    print(f"   Found {len(keywords)} keywords")
    
    print("   Adding patterns to AhoCorasick...")
    for i, keyword in enumerate(keywords):
        print(f"     Adding keyword {i+1}/{len(keywords)}: {keyword}")
        keyword_matcher.add_pattern(keyword)
    
    print("   Building AhoCorasick automaton...")
    keyword_matcher.build()
    print("   ✓ Keywords loaded successfully")
    
except Exception as e:
    print(f"   ✗ Error loading keywords: {e}")
    import traceback
    traceback.print_exc()

print("Debug test completed.")