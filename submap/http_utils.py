"""HTTP probing, technology detection, session creation, and takeover checks."""
from typing import Dict, Any, List, Tuple
import time, re
from aiohttp import ClientTimeout
from aiohttp_retry import RetryClient, ExponentialRetry

from . import setup_logging, TECH_PATTERNS, TAKEOVER_FINGERPRINTS
logger = setup_logging()


def detect_technologies(content: str, headers: Dict[str, str]) -> List[str]:
    technologies = []
    content_lower = content.lower()
    for tech, patterns in TECH_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, content_lower):
                technologies.append(tech)
                break
    server = headers.get('Server', '').lower()
    if 'nginx' in server:
        technologies.append('nginx')
    elif 'apache' in server:
        technologies.append('apache')
    powered_by = headers.get('X-Powered-By', '').lower()
    if 'php' in powered_by:
        technologies.append('PHP')
    elif 'asp.net' in powered_by:
        technologies.append('ASP.NET')
    return list(set(technologies))


async def probe_http_advanced(session: RetryClient, host: str) -> Dict[str, Any]:
    result = {
        'url': None,
        'status': None,
        'title': None,
        'server': None,
        'content_length': None,
        'content_hash': None,
        'redirect_chain': None,
        'response_time': None,
        'ssl_cert': None,
        'technologies': None
    }
    async def fetch(url):
        start_time = time.time()
        redirects = []
        try:
            async with session.get(url, timeout=ClientTimeout(total=10), allow_redirects=True, ssl=False) as resp:
                response_time = time.time() - start_time
                content = await resp.text()
                for redirect in resp.history:
                    redirects.append(str(redirect.url))
                title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE | re.DOTALL)
                title = title_match.group(1).strip() if title_match else None
                import hashlib
                content_hash = hashlib.md5(content.encode()).hexdigest()
                technologies = detect_technologies(content, resp.headers)
                ssl_cert = None
                if url.startswith('https'):
                    ssl_cert = "Valid"
                return {
                    'url': url,
                    'status': resp.status,
                    'title': title,
                    'server': resp.headers.get('Server'),
                    'content_length': len(content),
                    'content_hash': content_hash,
                    'redirect_chain': ','.join(redirects) if redirects else None,
                    'response_time': round(response_time, 2),
                    'ssl_cert': ssl_cert,
                    'technologies': ','.join(technologies) if technologies else None
                }
        except Exception:
            return None
    for scheme in ['https', 'http']:
        url = f"{scheme}://{host}/"
        res = await fetch(url)
        if res:
            return res
    return result


def create_retry_session() -> RetryClient:
    retry_options = ExponentialRetry(
        attempts=3,
        start_timeout=1,
        max_timeout=10,
        factor=2.0,
        statuses={500, 502, 503, 504, 429}
    )
    from aiohttp import TCPConnector, ClientSession
    connector = TCPConnector(limit=100, limit_per_host=10, ttl_dns_cache=300, ssl=False)
    timeout = ClientTimeout(total=30, connect=10, sock_read=20)
    base_session = ClientSession(connector=connector, timeout=timeout)
    return RetryClient(client_session=base_session, retry_options=retry_options)


async def check_takeover(session: RetryClient, subdomain: str, dns_results: Dict[str, List[str]]) -> Tuple[bool, str, str]:
    cnames = dns_results.get('CNAME', [])
    for cname in cnames:
        cname_lower = cname.lower()
        for service, fingerprints in TAKEOVER_FINGERPRINTS.items():
            if service in cname_lower:
                try:
                    async with session.get(f"http://{subdomain}", timeout=ClientTimeout(total=5)) as resp:
                        content = await resp.text()
                        for fingerprint in fingerprints:
                            if fingerprint in content:
                                return (True, service, fingerprint)
                except Exception:
                    pass
    return (False, "", "")


# Screenshots removed - function removed to simplify package
