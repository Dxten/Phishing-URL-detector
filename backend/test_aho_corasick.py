from data_structures import AhoCorasick

# Test Aho-Corasick implementation
print("Testing Aho-Corasick implementation...")

try:
    matcher = AhoCorasick()
    patterns = ['login', 'secure', 'account', 'verify']
    
    print("Adding patterns...")
    for pattern in patterns:
        matcher.add_pattern(pattern)
    
    print("Building automaton...")
    matcher.build()
    
    print("Testing search...")
    text = "https://secure-login-example.com"
    matches = matcher.search(text)
    print(f"Found matches: {matches}")
    
    print("Test completed successfully!")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()