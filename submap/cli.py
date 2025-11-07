"""Command-line interface for submap package.
This module contains argument parsing and the `main()` entrypoint that wraps
`scanner.run_comprehensive_scan` from the package.
"""
import argparse
import asyncio
from typing import Optional

from . import setup_logging
from .scanner import run_comprehensive_scan
from .database import Storage


def parse_args():
    p = argparse.ArgumentParser(
        description="SubMap - Advanced subdomain enumeration & asset discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Passive scan only (safe)
  python -m submap.cli --domain example.com --authorized

  # Active scan with bruteforce
  python -m submap.cli --domain example.com --authorized --active --modules bruteforce

    # Full scan with all features
    python -m submap.cli --domain example.com --authorized --active --tech-detect
"""
    )

    p.add_argument('--domain', required=True, help='Target domain (e.g., example.com)')
    p.add_argument('--db', default='submap_pro.db', help='SQLite database path')
    p.add_argument('--concurrency', type=int, default=20, help='Concurrent tasks (default: 20)')
    p.add_argument('--authorized', action='store_true', required=True, help='Confirm authorization (REQUIRED)')

    # Active mode options
    p.add_argument('--active', action='store_true', help='Enable active scanning')
    p.add_argument('--modules', default='bruteforce,portscan', 
                   help='Active modules: bruteforce,portscan,recursive (comma-separated)')
    p.add_argument('--wordlist', help='Path to subdomain wordlist file')

    # API keys
    p.add_argument('--vt-api-key', help='VirusTotal API key')

    # Feature flags
    p.add_argument('--tech-detect', action='store_true', help='Enable technology detection')
    p.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')

    return p.parse_args()


def load_wordlist(filepath: Optional[str] = None):
    from pathlib import Path
    from . import BUILTIN_WORDLIST
    if filepath and Path(filepath).exists():
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            words = [line.strip().lower() for line in f if line.strip()]
        return words
    return BUILTIN_WORDLIST


def main():
    args = parse_args()
    logger = setup_logging(args.verbose)

    modules = set(args.modules.split(',')) if args.modules else set()

    # Load wordlist if provided - scanner can also accept a path
    wordlist = load_wordlist(args.wordlist) if args.wordlist else None

    try:
        asyncio.run(run_comprehensive_scan(
            domain=args.domain,
            db_path=args.db,
            concurrency=args.concurrency,
            authorized=args.authorized,
            active=args.active,
            modules=modules,
            wordlist_path=args.wordlist,
            vt_api_key=args.vt_api_key,
            tech_detect=args.tech_detect
        ))
    except KeyboardInterrupt:
        logger.warning("\n⚠️  Scan interrupted by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)


if __name__ == '__main__':
    main()
