import unittest
import sys
import os

# Add the backend directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from app import app

class TestAPI(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
    
    def test_home_endpoint(self):
        result = self.app.get('/')
        self.assertEqual(result.status_code, 200)
        self.assertIn(b'Phishing URL Detector API', result.data)
    
    def test_invalid_endpoint(self):
        result = self.app.get('/invalid')
        self.assertEqual(result.status_code, 404)

if __name__ == '__main__':
    unittest.main()