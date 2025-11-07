"""submap package init
Exports constants and logging setup used by submodules.
"""
from typing import List

# Built-in wordlist for subdomain bruteforcing
BUILTIN_WORDLIST: List[str] = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "autodiscover", "autoconfig", "m", "imap", "test", "blog", "dev", "www2",
    "admin", "forum", "news", "vpn", "mail2", "mysql", "old", "support", "mobile",
    "mx", "static", "docs", "beta", "shop", "secure", "demo", "wiki", "web",
    "media", "email", "images", "img", "intranet", "portal", "video", "api",
    "cdn", "stats", "staging", "server", "chat", "my", "svn", "sites", "proxy",
    "crm", "cms", "backup", "remote", "db", "forums", "store", "files", "app",
    "owa", "en", "sms", "office", "exchange", "v1", "v2", "cloud", "internal"
]

COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
    3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 27017
]

# Subdomain takeover fingerprints (subset)
TAKEOVER_FINGERPRINTS = {
    "github": ["There isn't a GitHub Pages site here", "404: Not Found"],
    "heroku": ["no-such-app.herokuapp.com", "No such app"],
    "aws-s3": ["NoSuchBucket", "The specified bucket does not exist"],
    "azure": ["404 Web Site not found", "Azure Web Sites"],
    "shopify": ["Sorry, this shop is currently unavailable"],
}

TECH_PATTERNS = {
    "wordpress": [r"wp-content", r"wp-includes", r"/wp-json/"],
    "drupal": [r"Drupal", r"/sites/default/", r"drupal.js"],
    "nginx": [r"nginx"],
    "apache": [r"apache"],
}


def setup_logging(verbose: bool = False):
    """Configure logging with optional colors and formatting.

    Returns a logger configured for the package modules.
    """
    import logging

    level = logging.DEBUG if verbose else logging.INFO

    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': '\033[36m',    # Cyan
            'INFO': '\033[32m',     # Green
            'WARNING': '\033[33m',  # Yellow
            'ERROR': '\033[31m',    # Red
            'CRITICAL': '\033[35m', # Magenta
        }
        RESET = '\033[0m'

        def format(self, record):
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}{record.levelname}{self.RESET}"
            return super().format(record)

    handler = logging.StreamHandler()
    handler.setFormatter(ColoredFormatter('%(levelname)s - %(message)s'))

    logger = logging.getLogger('submap')
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)

    return logger


__all__ = [
    'BUILTIN_WORDLIST', 'COMMON_PORTS', 'TAKEOVER_FINGERPRINTS', 'TECH_PATTERNS', 'setup_logging'
]
