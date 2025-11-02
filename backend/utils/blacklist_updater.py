import requests
import json
from datetime import datetime
from pathlib import Path
from typing import List, Set
import tldextract
from config import Config


class BlacklistUpdater:
    """Automatically update phishing blacklists from threat intelligence feeds"""
    
    def __init__(self):
        self.phishtank_url = Config.PHISHTANK_API
        self.openphish_url = Config.OPENPHISH_API
        self.blacklist_file = Config.PHISHING_URLS_FILE
        self.update_log = Config.LOGS_DIR / 'blacklist_updates.log'
    
    def update_from_phishtank(self) -> Set[str]:
        """Fetch latest phishing URLs from PhishTank"""
        try:
            print("Fetching from PhishTank...")
            response = requests.get(self.phishtank_url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            domains = set()
            
            for entry in data:
                if entry.get('verified') == 'yes':
                    url = entry.get('url', '')
                    domain = self._extract_domain(url)
                    if domain:
                        domains.add(domain)
            
            print(f"✓ Fetched {len(domains)} domains from PhishTank")
            return domains
        
        except Exception as e:
            print(f"✗ Error fetching from PhishTank: {e}")
            return set()
    
    def update_from_openphish(self) -> Set[str]:
        """Fetch latest phishing URLs from OpenPhish"""
        try:
            print("Fetching from OpenPhish...")
            response = requests.get(self.openphish_url, timeout=30)
            response.raise_for_status()
            
            urls = response.text.strip().split('\n')
            domains = set()
            
            for url in urls:
                domain = self._extract_domain(url)
                if domain:
                    domains.add(domain)
            
            print(f"✓ Fetched {len(domains)} domains from OpenPhish")
            return domains
        
        except Exception as e:
            print(f"✗ Error fetching from OpenPhish: {e}")
            return set()
    
    def update_blacklist(self) -> bool:
        """Update blacklist from all sources"""
        try:
            print(f"\n{'='*50}")
            print(f"Blacklist Update Started: {datetime.now()}")
            print(f"{'='*50}\n")
            
            # Fetch from sources
            phishtank_domains = self.update_from_phishtank()
            openphish_domains = self.update_from_openphish()
            
            # Combine and deduplicate
            all_domains = phishtank_domains.union(openphish_domains)
            
            # Load existing blacklist
            existing_domains = self._load_existing_blacklist()
            
            # Merge
            all_domains.update(existing_domains)
            
            # Save to file
            self._save_blacklist(all_domains)
            
            # Log update
            self._log_update(len(all_domains), len(phishtank_domains), len(openphish_domains))
            
            print(f"\n✓ Blacklist updated successfully!")
            print(f"Total domains: {len(all_domains)}")
            print(f"New from PhishTank: {len(phishtank_domains)}")
            print(f"New from OpenPhish: {len(openphish_domains)}")
            
            return True
        
        except Exception as e:
            print(f"✗ Error updating blacklist: {e}")
            return False
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            return domain.lower() if domain != '.' else ''
        except:
            return ''
    
    def _load_existing_blacklist(self) -> Set[str]:
        """Load existing blacklist"""
        domains = set()
        try:
            if self.blacklist_file.exists():
                with open(self.blacklist_file, 'r') as f:
                    for line in f:
                        domain = line.strip()
                        if domain and not domain.startswith('#'):
                            domains.add(domain)
        except Exception as e:
            print(f"Warning: Could not load existing blacklist: {e}")
        return domains
    
    def _save_blacklist(self, domains: Set[str]):
        """Save blacklist to file"""
        with open(self.blacklist_file, 'w') as f:
            f.write(f"# Phishing URL Blacklist\n")
            f.write(f"# Last updated: {datetime.now()}\n")
            f.write(f"# Total entries: {len(domains)}\n\n")
            
            for domain in sorted(domains):
                f.write(f"{domain}\n")
    
    def _log_update(self, total: int, phishtank: int, openphish: int):
        """Log update to file"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'total_domains': total,
            'phishtank_count': phishtank,
            'openphish_count': openphish
        }
        
        try:
            logs = []
            if self.update_log.exists():
                with open(self.update_log, 'r') as f:
                    logs = json.load(f)
            
            logs.append(log_entry)
            
            # Keep only last 100 entries
            logs = logs[-100:]
            
            with open(self.update_log, 'w') as f:
                json.dump(logs, f, indent=2)
        
        except Exception as e:
            print(f"Warning: Could not write update log: {e}")
    
    def schedule_updates(self):
        """Schedule periodic updates (use with APScheduler)"""
        from apscheduler.schedulers.background import BackgroundScheduler
        
        scheduler = BackgroundScheduler()
        scheduler.add_job(
            self.update_blacklist,
            'interval',
            hours=Config.BLACKLIST_UPDATE_INTERVAL
        )
        scheduler.start()
        
        print(f"✓ Scheduled blacklist updates every {Config.BLACKLIST_UPDATE_INTERVAL} hours")
        return scheduler


# Standalone script for manual updates
if __name__ == '__main__':
    Config.ensure_directories()
    updater = BlacklistUpdater()
    updater.update_blacklist()