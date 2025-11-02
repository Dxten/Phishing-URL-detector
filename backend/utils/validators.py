from urllib.parse import urlparse

def is_valid_url(url):
    """
    Validate if the provided string is a valid URL.
    
    Args:
        url (str): The URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def extract_domain(url):
    """
    Extract the domain from a URL.
    
    Args:
        url (str): The URL to extract domain from
        
    Returns:
        str: The domain name
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc
    except Exception:
        return ""