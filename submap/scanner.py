"""Main scanning orchestration and port scanning helpers."""
from typing import List, Set, Dict, Any, Optional
import asyncio, time
from concurrent.futures import ThreadPoolExecutor
from .database import Storage
from .dns_utils import (
    detect_wildcard, resolve_name_advanced, discover_recursive, dns_lookup_cached,
    fetch_crtsh, fetch_hackertarget, fetch_virustotal
)
from .http_utils import probe_http_advanced, create_retry_session, check_takeover
from .reporter import Reporter
from . import COMMON_PORTS, setup_logging
from aiohttp_retry import RetryClient
# async progress bar for asyncio tasks
from tqdm.asyncio import tqdm as async_tqdm

logger = setup_logging()


async def port_scan_advanced(ip: str, ports: List[int], timeout: float = 1.0) -> List[Dict[str, Any]]:
    results = []
    async def scan_port(port: int):
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
            banner = await grab_banner_advanced(reader, writer, port)
            service = identify_service_advanced(port, banner)
            writer.close()
            await writer.wait_closed()
            return {
                'port': port,
                'state': 'open',
                'service': service,
                'banner': banner
            }
        except Exception:
            return None
    tasks = [scan_port(p) for p in ports]
    scan_results = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in scan_results if r is not None]


async def grab_banner_advanced(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int):
    probes = {
        21: b"",
        22: b"",
        25: b"EHLO banner\r\n",
        80: b"GET / HTTP/1.1\r\nHost: test\r\n\r\n",
        143: b"A001 CAPABILITY\r\n",
    }
    try:
        probe = probes.get(port, b"")
        if probe:
            writer.write(probe)
            await writer.drain()
        banner = await asyncio.wait_for(reader.read(1024), timeout=3.0)
        return banner.decode('utf-8', errors='ignore').strip()[:200]
    except Exception:
        return None


def identify_service_advanced(port: int, banner: Optional[str]) -> str:
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    service = services.get(port, f"Unknown ({port})")
    if banner:
        bl = banner.lower()
        if 'ssh' in bl:
            if 'openssh' in bl:
                import re
                version = re.search(r'openssh[_\s]([\d.]+)', bl)
                service = f"OpenSSH {version.group(1)}" if version else "OpenSSH"
        elif 'server:' in bl or 'http' in bl:
            import re
            server_match = re.search(r'server:\s*([^\r\n]+)', bl)
            if server_match:
                service = f"HTTP ({server_match.group(1)})"
    return service


async def bruteforce_subdomains(domain: str, wordlist: List[str], 
                                executor: ThreadPoolExecutor, 
                                concurrency: int = 50) -> Set[str]:
    found = set()
    sem = asyncio.Semaphore(concurrency)
    async def try_word(word: str):
        async with sem:
            candidate = f"{word}.{domain}"
            loop = asyncio.get_event_loop()
            try:
                result = await loop.run_in_executor(
                    executor,
                    dns_lookup_cached,
                    candidate,
                    'A'
                )
                if result:
                    found.add(candidate)
                    return candidate
            except Exception:
                pass
            return None
    tasks = [try_word(word) for word in wordlist]
    for coro in asyncio.as_completed(tasks):
        res = await coro
        # we avoid tqdm in library code; caller may wrap with progress
    return found


async def run_comprehensive_scan(
    domain: str,
    db_path: str,
    concurrency: int,
    authorized: bool,
    active: bool,
    modules: Set[str],
    wordlist_path: Optional[str],
    vt_api_key: Optional[str],
    tech_detect: bool
):
    if not authorized:
        logger.error("You must pass --authorized to proceed")
        return
    if active:
        print("\n" + "="*70)
        print("⚠️  WARNING: ACTIVE MODE ENABLED")
        print("="*70)
        response = input("\nType 'YES I AM AUTHORIZED' to continue: ")
        if response != "YES I AM AUTHORIZED":
            logger.error("Authorization not confirmed. Aborting.")
            return
    logger.info(f"Starting comprehensive scan for {domain}")
    storage = Storage(db_path)
    executor = ThreadPoolExecutor(max_workers=20)
    session = create_retry_session()
    # Create reporter instance for this scan
    reporter = Reporter(storage, domain)
    try:
        all_subdomains = set()

        # wildcard check
        is_wildcard = await detect_wildcard(domain, executor)

        # PASSIVE ENUMERATION
        logger.info("PHASE 1: PASSIVE ENUMERATION")
        passive_sources = []

        try:
            crtsh_subs = await fetch_crtsh(session, domain)
            all_subdomains.update(crtsh_subs)
            passive_sources.append(('crt.sh', len(crtsh_subs)))
        except Exception as e:
            logger.debug(f"crt.sh passive error: {e}")

        try:
            ht_subs = await fetch_hackertarget(session, domain)
            all_subdomains.update(ht_subs)
            passive_sources.append(('HackerTarget', len(ht_subs)))
        except Exception as e:
            logger.debug(f"HackerTarget passive error: {e}")

        if vt_api_key:
            try:
                vt_subs = await fetch_virustotal(session, domain, vt_api_key)
                all_subdomains.update(vt_subs)
                passive_sources.append(('VirusTotal', len(vt_subs)))
            except Exception as e:
                logger.debug(f"VirusTotal passive error: {e}")

        logger.info("\nPassive Enumeration Results:")
        for src, cnt in passive_sources:
            logger.info(f"  {src}: {cnt} subdomains")
        logger.info(f"Total unique (passive): {len(all_subdomains)}")

        #SKIP ACTIVE ENUMERATION
        if active == False:
            logger.info("PHASE 2: SKIPPING ACTIVE ENUMERATION PHASE AS PER CONFIGURATION")
            
        # ACTIVE ENUMERATION
        if active:
            logger.info("PHASE 2: ACTIVE ENUMERATION")
            if 'bruteforce' in modules:
                # load wordlist if provided via wordlist_path
                from .cli import load_wordlist
                wordlist = load_wordlist(wordlist_path) if wordlist_path else None
                if wordlist is None:
                    logger.info("No custom wordlist provided; using package default")
                    wordlist = []
                logger.info(f"Starting bruteforce with {len(wordlist)} words...")
                brute_subs = await bruteforce_subdomains(domain, wordlist, executor, concurrency)
                for sub in brute_subs:
                    storage.upsert_subdomain(sub, method="bruteforce", is_wildcard=is_wildcard)
                all_subdomains.update(brute_subs)

            if 'recursive' in modules:
                logger.info("Attempting recursive subdomain discovery...")
                recursive_subs = await discover_recursive(all_subdomains, executor)
                all_subdomains.update(recursive_subs)

        # PROCESS & PROBE
        logger.info("PHASE 3: DNS RESOLUTION & HTTP PROBING")
        all_list = sorted(all_subdomains)
        logger.info(f"Processing {len(all_list)} total subdomains...")

        sem = asyncio.Semaphore(concurrency)

        async def process_subdomain(subdomain: str):
            async with sem:
                sid = storage.upsert_subdomain(subdomain, method="passive", is_wildcard=is_wildcard)
                dns_results = await resolve_name_advanced(executor, subdomain)
                ips = dns_results.get('A', [])
                for rtype, values in dns_results.items():
                    for v in values:
                        storage.insert_resolution(sid, rtype, v)

                if ips:
                    probe_data = await probe_http_advanced(session, subdomain)
                    storage.insert_http_probe(sid, probe_data)
                    is_vuln, service, evidence = await check_takeover(session, subdomain, dns_results)
                    if is_vuln:
                        storage.insert_takeover_check(sid, True, service, evidence)


                    if active and 'portscan' in modules:
                        ip = ips[0]
                        port_results = await port_scan_advanced(ip, COMMON_PORTS, timeout=0.5)
                        for pinfo in port_results:
                            storage.insert_port_scan(sid, ip, pinfo['port'], pinfo['state'], pinfo['service'], pinfo['banner'])

        # run tasks in batches to avoid huge concurrency spikes
        tasks = [process_subdomain(s) for s in all_list]
        if tasks:
            
            await async_tqdm.gather(*tasks, desc="Processing subdomains (CTRL+C to end early if stuck)")

        # REPORT
        logger.info("PHASE 4: GENERATING REPORTS")
        stats = storage.get_stats()
        logger.info(f"Total subdomains: {stats['total_subdomains']}")
        
        # Generate domain-specific reports
        reporter = Reporter(storage, domain)
        report_paths = reporter.export_all()
        
        logger.info("\n✅ Scan complete!")
        logger.info("📁 Reports generated in reports/%s/%s:" % (domain, reporter.report_dir.name))
        logger.info(f"   • {report_paths['json']} (detailed)")
        logger.info(f"   • {report_paths['csv']} (spreadsheet)") 
        logger.info(f"   • {report_paths['html']} (dashboard)")

    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
    finally:
        try:
            await session.close()
        except Exception:
            pass
        storage.close()
        executor.shutdown(wait=False)
