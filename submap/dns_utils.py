"""DNS utility functions for submap
Includes passive sources and advanced resolution helpers.
"""
from typing import Set, List, Dict, Optional
import asyncio, uuid
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
import dns.resolver

from aiohttp import ClientTimeout
from aiohttp_retry import RetryClient


from . import setup_logging
logger = setup_logging()

# Certificate Transparency
async def fetch_crtsh(session: RetryClient, domain: str) -> Set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with session.get(url, timeout=ClientTimeout(total=30)) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
            names = set()
            for entry in data:
                name = entry.get("name_value") or entry.get("common_name")
                if name:
                    for n in str(name).split("\n"):
                        n = n.strip().lower()
                        if n and n.endswith(domain):
                            names.add(n.lstrip('*.'))
            return names
    except Exception as e:
        logger.debug(f"crt.sh error: {e}")
        return set()


async def fetch_hackertarget(session: RetryClient, domain: str) -> Set[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with session.get(url, timeout=ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                return set()
            text = await resp.text()
            names = set()
            for line in text.split('\n'):
                if ',' in line:
                    subdomain = line.split(',')[0].strip().lower()
                    if subdomain.endswith(domain):
                        names.add(subdomain)
            return names
    except Exception as e:
        logger.debug(f"HackerTarget error: {e}")
        return set()


async def fetch_virustotal(session: RetryClient, domain: str, api_key: Optional[str] = None) -> Set[str]:
    if not api_key:
        return set()
    url = f"https://www.virustotal.com/vtapi/v2/domain/report"
    params = {"apikey": api_key, "domain": domain}
    try:
        async with session.get(url, params=params, timeout=ClientTimeout(total=20)) as resp:
            if resp.status != 200:
                return set()
            data = await resp.json()
            subdomains = data.get('subdomains', [])
            return set(s.lower() for s in subdomains if s.endswith(domain))
    except Exception as e:
        logger.debug(f"VirusTotal error: {e}")
        return set()


# Wildcard detection
async def detect_wildcard(domain: str, executor: ThreadPoolExecutor) -> bool:
    random_subs = [f"{uuid.uuid4().hex[:8]}.{domain}" for _ in range(3)]
    async def check_random(subdomain):
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(
                executor,
                lambda: dns.resolver.resolve(subdomain, 'A', lifetime=3)
            )
            return len(result) > 0
        except Exception:
            return False
    results = await asyncio.gather(*[check_random(s) for s in random_subs])
    is_wildcard = sum(results) >= 2
    if is_wildcard:
        logger.warning(f"Wildcard DNS detected for {domain} - results may include false positives")
    return is_wildcard


# Caching helper
@lru_cache(maxsize=1000)
def dns_lookup_cached(name: str, rtype: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(name, rtype, lifetime=5)
        return [r.to_text() for r in answers]
    except Exception:
        return []


async def resolve_name_advanced(executor: ThreadPoolExecutor, name: str) -> Dict[str, List[str]]:
    loop = asyncio.get_event_loop()
    results = {"A": [], "AAAA": [], "CNAME": [], "MX": [], "NS": [], "TXT": []}
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
    async def resolve_type(rtype: str):
        return await loop.run_in_executor(executor, dns_lookup_cached, name, rtype)
    tasks = {rtype: resolve_type(rtype) for rtype in record_types}
    resolved = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for rtype, result in zip(record_types, resolved):
        if isinstance(result, list):
            results[rtype] = result
    return results


async def discover_recursive(base_domains: Set[str], executor: ThreadPoolExecutor) -> Set[str]:
    recursive_patterns = ['api', 'v1', 'v2', 'staging', 'dev', 'test']
    found = set()
    loop = asyncio.get_event_loop()
    async def try_recursive(subdomain: str):
        for pattern in recursive_patterns:
            candidate = f"{pattern}.{subdomain}"
            try:
                result = await loop.run_in_executor(
                    executor,
                    lambda: dns.resolver.resolve(candidate, 'A', lifetime=2)
                )
                if result:
                    found.add(candidate)
            except Exception:
                pass
    tasks = [try_recursive(domain) for domain in list(base_domains)[:50]]
    await asyncio.gather(*tasks, return_exceptions=True)
    return found
