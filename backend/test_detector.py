from detector import PhishingDetector

# Test detector initialization
print("Testing PhishingDetector initialization...")

try:
    print("Creating PhishingDetector instance...")
    detector = PhishingDetector()
    print("Detector created successfully!")
    print(f"Blacklist size: {detector.blacklist_hashset.size()}")
    print(f"Whitelist size: {detector.whitelist.size()}")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()