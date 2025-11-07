"""Database storage for submap scans (SQLite)
Contains DB_SCHEMA and Storage class.
"""
from typing import Dict, Any, Optional
import sqlite3, time, csv, json
from pathlib import Path

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT UNIQUE,
    first_seen INTEGER,
    last_seen INTEGER,
    discovery_method TEXT,
    is_wildcard INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS resolutions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER,
    record_type TEXT,
    value TEXT,
    ttl INTEGER,
    FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
);

CREATE TABLE IF NOT EXISTS http_probe (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER,
    url TEXT,
    status INTEGER,
    title TEXT,
    server_header TEXT,
    content_length INTEGER,
    content_hash TEXT,
    redirect_chain TEXT,
    response_time REAL,
    ssl_cert TEXT,
    technologies TEXT,
    checked_at INTEGER,
    FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
);

CREATE TABLE IF NOT EXISTS port_scan (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER,
    ip_address TEXT,
    port INTEGER,
    state TEXT,
    service TEXT,
    banner TEXT,
    scanned_at INTEGER,
    FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
);
CREATE TABLE IF NOT EXISTS takeover_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER,
    vulnerable INTEGER,
    service TEXT,
    evidence TEXT,
    checked_at INTEGER,
    FOREIGN KEY(subdomain_id) REFERENCES subdomains(id)
);

CREATE INDEX IF NOT EXISTS idx_subdomain_domain ON subdomains(domain);
CREATE INDEX IF NOT EXISTS idx_resolution_subdomain ON resolutions(subdomain_id);
"""


class Storage:
    def __init__(self, path: str = "submap_pro.db"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        cur = self.conn.cursor()
        cur.executescript(DB_SCHEMA)
        self.conn.commit()

    def upsert_subdomain(self, domain: str, method: str = "passive", is_wildcard: bool = False) -> int:
        now = int(time.time())
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM subdomains WHERE domain = ?", (domain,))
        row = cur.fetchone()
        if row:
            sid = row[0]
            cur.execute("UPDATE subdomains SET last_seen = ?, is_wildcard = ? WHERE id = ?", 
                       (now, int(is_wildcard), sid))
        else:
            cur.execute(
                "INSERT INTO subdomains(domain, first_seen, last_seen, discovery_method, is_wildcard) VALUES (?, ?, ?, ?, ?)",
                (domain, now, now, method, int(is_wildcard))
            )
            sid = cur.lastrowid
        self.conn.commit()
        return sid

    def insert_resolution(self, subdomain_id: int, rtype: str, value: str, ttl: int = 0):
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO resolutions(subdomain_id, record_type, value, ttl) VALUES (?, ?, ?, ?)",
            (subdomain_id, rtype, value, ttl)
        )
        self.conn.commit()

    def insert_http_probe(self, subdomain_id: int, data: Dict[str, Any]):
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO http_probe(subdomain_id, url, status, title, server_header, 
               content_length, content_hash, redirect_chain, response_time, ssl_cert, 
               technologies, checked_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                subdomain_id, data.get('url'), data.get('status'), data.get('title'),
                data.get('server'), data.get('content_length'), data.get('content_hash'),
                data.get('redirect_chain'), data.get('response_time'), data.get('ssl_cert'),
                data.get('technologies'), int(time.time())
            )
        )
        self.conn.commit()

    def insert_port_scan(self, subdomain_id: int, ip: str, port: int, 
                        state: str, service: Optional[str], banner: Optional[str]):
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO port_scan(subdomain_id, ip_address, port, state, service, banner, scanned_at) 
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (subdomain_id, ip, port, state, service, banner, int(time.time()))
        )
        self.conn.commit()

    def insert_screenshot(self, subdomain_id: int, url: str, filepath: str):
        # screenshots removed completely — kept for historical reasons but no longer supported
        raise NotImplementedError("Screenshot storage has been removed from this build")

    def insert_takeover_check(self, subdomain_id: int, vulnerable: bool, service: str, evidence: str):
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO takeover_checks(subdomain_id, vulnerable, service, evidence, checked_at) 
               VALUES (?, ?, ?, ?, ?)""",
            (subdomain_id, int(vulnerable), service, evidence, int(time.time()))
        )
        self.conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        cur = self.conn.cursor()
        stats = {}
        cur.execute("SELECT COUNT(*) as total FROM subdomains")
        stats['total_subdomains'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) as alive FROM http_probe WHERE status IS NOT NULL AND status < 400")
        stats['alive_hosts'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(DISTINCT port) as open_ports FROM port_scan WHERE state = 'open'")
        stats['open_ports'] = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) as vulns FROM takeover_checks WHERE vulnerable = 1")
        stats['takeover_vulns'] = cur.fetchone()[0]
        return stats

    def export_json(self, outpath: str = "submap_results.json"):
        cur = self.conn.cursor()
        out = {"scan_info": {}, "subdomains": []}
        out["scan_info"] = {
            "generated_at": int(time.time()),
            "stats": self.get_stats()
        }
        cur.execute("SELECT * FROM subdomains ORDER BY domain")
        for row in cur.fetchall():
            sid = row['id']
            entry = {
                "domain": row['domain'],
                "first_seen": row['first_seen'],
                "last_seen": row['last_seen'],
                "discovery_method": row['discovery_method'],
                "is_wildcard": bool(row['is_wildcard']),
                "resolutions": [],
                "http": [],
                "ports": [],
                "takeover": []
            }
            cur.execute("SELECT * FROM resolutions WHERE subdomain_id = ?", (sid,))
            entry["resolutions"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM http_probe WHERE subdomain_id = ?", (sid,))
            entry["http"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM port_scan WHERE subdomain_id = ?", (sid,))
            entry["ports"] = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT * FROM takeover_checks WHERE subdomain_id = ?", (sid,))
            entry["takeover"] = [dict(r) for r in cur.fetchall()]
            out["subdomains"].append(entry)
        with open(outpath, 'w', encoding='utf-8') as f:
            json.dump(out, f, indent=2)
        return outpath

    def export_csv(self, outpath: str = "submap_results.csv"):
        cur = self.conn.cursor()
        with open(outpath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Domain', 'Discovery Method', 'IP Addresses', 'HTTP Status', 
                'Title', 'Server', 'Technologies', 'Open Ports', 'Takeover Risk'
            ])
            cur.execute("SELECT * FROM subdomains ORDER BY domain")
            for row in cur.fetchall():
                sid = row['id']
                domain = row['domain']
                method = row['discovery_method']
                cur.execute("SELECT value FROM resolutions WHERE subdomain_id = ? AND record_type = 'A'", (sid,))
                ips = ', '.join([r[0] for r in cur.fetchall()])
                cur.execute("SELECT status, title, server_header, technologies FROM http_probe WHERE subdomain_id = ? LIMIT 1", (sid,))
                http = cur.fetchone()
                status = http['status'] if http else ''
                title = http['title'] if http else ''
                server = http['server_header'] if http else ''
                tech = http['technologies'] if http else ''
                cur.execute("SELECT port FROM port_scan WHERE subdomain_id = ? AND state = 'open'", (sid,))
                ports = ', '.join([str(r[0]) for r in cur.fetchall()])
                cur.execute("SELECT vulnerable FROM takeover_checks WHERE subdomain_id = ? AND vulnerable = 1", (sid,))
                takeover = 'YES' if cur.fetchone() else 'NO'
                writer.writerow([domain, method, ips, status, title, server, tech, ports, takeover])
        return outpath

    def export_html(self, outpath: str = "submap_results.html"):
        stats = self.get_stats()
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SubMap Report</title>
    <style>
        body {{ 
            font-family: 
            Arial, sans-serif; 
            margin: 20px;
            background: #f5f5f5; }}
            
        .container {{ 
        max-width: 1200px; 
        margin: 0 auto; 
        background: white; 
        padding: 20px; 
        border-radius: 8px; }}
        
        h1 {{ 
        color: #333; 
        border-bottom: 3px solid #4CAF50;
        padding-bottom: 10px; }}
        
        .stats {{
            display: grid;
        grid-template-columns: repeat(4, 1fr);
        gap: 15px;
        margin: 20px 0; }}
        
        .stat-card {{ 
        background: #4CAF50; 
                     color: white; 
                     padding: 20px; 
                     border-radius: 8px;
                     text-align: center; }}
                     
        .stat-card h3 {{ 
        margin: 0;
        font-size: 32px; }}
        
        .stat-card p {{
            margin: 5px 0 0 0; opacity: 0.9; }}
        
        table {{
            width: 100%; 
            border-collapse: collapse;
            margin: 20px 0; }}
        
        th {{
            background: #4CAF50;
            color: white;
            padding: 12px;
            text-align: left; }}
        
        td {{ 
        padding: 10px;
        border-bottom: 1px solid #ddd; }}
        
        tr:hover {{ 
        background: #f9f9f9; }}
        
        .vulnerable {{
            color: red;
            font-weight: bold; }}
        
        .safe {{
            color: green; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SubMap - Reconnaissance Report</h1>
        <p><strong>Generated:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="stats">
            <div class="stat-card">
                <h3>{stats['total_subdomains']}</h3>
                <p>Total Subdomains</p>
            </div>
            <div class="stat-card">
                <h3>{stats['alive_hosts']}</h3>
                <p>Live Hosts</p>
            </div>
            <div class="stat-card">
                <h3>{stats['open_ports']}</h3>
                <p>Open Ports</p>
            </div>
            <div class="stat-card">
                <h3>{stats['takeover_vulns']}</h3>
                <p>Takeover Risks</p>
            </div>
        </div>
        
        <h2>Subdomain Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>IP Address</th>
                    <th>HTTP Status</th>
                    <th>Title</th>
                    <th>Technologies</th>
                    <th>Takeover Risk</th>
                </tr>
            </thead>
            <tbody>
"""
        cur = self.conn.cursor()
        cur.execute("""
            SELECT s.domain, r.value as ip, h.status, h.title, h.technologies, 
                   COALESCE(t.vulnerable, 0) as takeover
            FROM subdomains s
            LEFT JOIN resolutions r ON s.id = r.subdomain_id AND r.record_type = 'A'
            LEFT JOIN http_probe h ON s.id = h.subdomain_id
            LEFT JOIN takeover_checks t ON s.id = t.subdomain_id
            ORDER BY s.domain
        """)
        for row in cur.fetchall():
            takeover_class = 'vulnerable' if row['takeover'] else 'safe'
            takeover_text = 'VULNERABLE' if row['takeover'] else 'Safe'
            html += f"""
                <tr>
                    <td><strong>{row['domain']}</strong></td>
                    <td>{row['ip'] or 'N/A'}</td>
                    <td>{row['status'] or 'N/A'}</td>
                    <td>{row['title'] or 'N/A'}</td>
                    <td>{row['technologies'] or 'N/A'}</td>
                    <td class=\"{takeover_class}\">{takeover_text}</td>
                </tr>
"""
        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""
        with open(outpath, 'w', encoding='utf-8') as f:
            f.write(html)
        return outpath

    def close(self):
        self.conn.close()
