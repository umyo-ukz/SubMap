"""
Handles report generation and organization for Submap
"""

import csv
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class Reporter:
    def __init__(self, storage, domain: str):
        """
        Initialize reporter for a specific domain
        
        Args:
            storage: Storage instance with database connection
            domain: Target domain for the scan
        """
        self.storage = storage
        self.domain = domain
        
        # Create reports directory if it doesn't exist
        self.base_dir = Path("reports")
        self.base_dir.mkdir(exist_ok=True)
        
        # Create domain-specific directory
        self.domain_dir = self.base_dir / self.domain
        self.domain_dir.mkdir(exist_ok=True)
        
        # Create timestamped directory for this scan
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = self.domain_dir / timestamp
        self.report_dir.mkdir(exist_ok=True)
        


    def export_all(self) -> Dict[str, str]:
        """
        Export all report formats and return paths
        
        Returns:
            Dict with keys 'json', 'csv', 'html' and values as paths
        """
        paths = {
            'json': self.export_json(),
            'csv': self.export_csv(),
            'html': self.export_html()
        }
        return paths
        
    def export_json(self) -> str:
        """Export comprehensive JSON report"""
        outpath = str(self.report_dir / "results.json")
        
        out = {
            "scan_info": {
                "domain": self.domain,
                "timestamp": datetime.now().isoformat(),
                "stats": self.storage.get_stats()
            },
            "subdomains": []
        }
        
        cur = self.storage.conn.cursor()
        cur.execute("SELECT * FROM subdomains ORDER BY domain")
        
        for row in cur.fetchall():
            entry = dict(row)
            sid = row['id']
            
            # Get DNS records
            cur.execute("SELECT * FROM resolutions WHERE subdomain_id = ?", (sid,))
            entry["resolutions"] = [dict(r) for r in cur.fetchall()]
            
            # HTTP probes
            cur.execute("SELECT * FROM http_probe WHERE subdomain_id = ?", (sid,))
            entry["http"] = [dict(r) for r in cur.fetchall()]
            
            # Port scans  
            cur.execute("SELECT * FROM port_scan WHERE subdomain_id = ?", (sid,))
            entry["ports"] = [dict(r) for r in cur.fetchall()]
            
            # Takeover checks
            cur.execute("SELECT * FROM takeover_checks WHERE subdomain_id = ?", (sid,))
            entry["takeover"] = [dict(r) for r in cur.fetchall()]
            
    
            
            out["subdomains"].append(entry)
        
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2)
        
        logger.info(f"JSON report saved to {outpath}")
        return outpath

    def export_csv(self) -> str:
        """Export flat CSV for spreadsheet analysis"""
        outpath = str(self.report_dir / "results.csv")
        
        cur = self.storage.conn.cursor() 
        
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
                
                # Get IPs
                cur.execute("SELECT value FROM resolutions WHERE subdomain_id = ? AND record_type = 'A'", (sid,))
                ips = ', '.join([r[0] for r in cur.fetchall()])
                
                # Get HTTP info
                cur.execute("SELECT * FROM http_probe WHERE subdomain_id = ?", (sid,))
                probe = cur.fetchone()
                if probe:
                    probe_dict = dict(probe)
                    status = probe_dict.get('status', '')
                    title = probe_dict.get('title', '')
                    server = probe_dict.get('server', '')
                    techs = probe_dict.get('technologies', '')
                else:
                    status = title = server = techs = ''
                
                # Get ports
                cur.execute("SELECT port FROM port_scan WHERE subdomain_id = ? AND state = 'open'", (sid,))
                ports = ', '.join(str(r[0]) for r in cur.fetchall())
                
                # Check takeover
                cur.execute("SELECT vulnerable FROM takeover_checks WHERE subdomain_id = ?", (sid,))
                takeover = cur.fetchone()
                takeover_risk = "Yes" if takeover and takeover[0] else "No"
                
                writer.writerow([
                    domain, method, ips, status, title, server, techs, ports, takeover_risk
                ])
        
        logger.info(f"CSV report saved to {outpath}")
        return outpath

    def export_html(self) -> str:
        """Export interactive HTML dashboard"""
        outpath = str(self.report_dir / "results.html")
        stats = self.storage.get_stats()
        
        # Read SQL data
        cur = self.storage.conn.cursor()
        cur.execute("SELECT * FROM subdomains ORDER BY domain")
        subdomains = []
        
        for row in cur.fetchall():
            sid = row['id']
            entry = dict(row)
            
            # Add IP addresses
            cur.execute("SELECT value FROM resolutions WHERE subdomain_id = ? AND record_type = 'A'", (sid,))
            entry['ips'] = [r[0] for r in cur.fetchall()]
            
            # Add HTTP probe data
            cur.execute("SELECT * FROM http_probe WHERE subdomain_id = ?", (sid,))
            probe = cur.fetchone()
            if probe:
                entry.update(dict(probe))
            
            # Add port data  
            cur.execute("SELECT * FROM port_scan WHERE subdomain_id = ? AND state = 'open'", (sid,))
            entry['open_ports'] = [dict(r) for r in cur.fetchall()]
            
            # Add takeover check
            cur.execute("SELECT * FROM takeover_checks WHERE subdomain_id = ?", (sid,))
            check = cur.fetchone()
            if check:
                entry['takeover'] = dict(check)
                
    
            
            subdomains.append(entry)
            
        # Generate HTML with embedded data
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>SubMap Report - {self.domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-card {{ 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card h3 {{ margin: 0; font-size: 2em; }}
        .stat-card p {{ margin: 5px 0 0; opacity: 0.9; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: #f8f9fa; }}
        tr:hover {{ background: #f5f5f5; }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }}
        .badge-success {{ background: #28a745; color: white; }}
        .badge-warning {{ background: #ffc107; color: black; }}
        .badge-danger {{ background: #dc3545; color: white; }}
        .modal {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
        }}
        .modal-content {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 20px;
            border-radius: 8px;
            max-width: 90%;
            max-height: 90%;
            overflow: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>SubMap Scan Report - {self.domain}</h1>
        <p>Scan completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
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

        <table id="resultsTable">
            <thead>
                <tr>
                    <th>Subdomain</th>
                    <th>IP Addresses</th>
                    <th>HTTP Status</th>
                    <th>Technologies</th>
                    <th>Open Ports</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                {self._generate_table_rows(subdomains)}
            </tbody>
        </table>
    </div>

    <div id="detailsModal" class="modal">
        <div class="modal-content">
            <h2>Subdomain Details</h2>
            <div id="modalContent"></div>
            <button onclick="closeModal()">Close</button>
        </div>
    </div>

    <script>
        const subdomains = {json.dumps(subdomains)};
        
        function showDetails(index) {{
            const modal = document.getElementById('detailsModal');
            const content = document.getElementById('modalContent');
            const data = subdomains[index];
            
            let html = `
                <h3>${{data.domain}}</h3>
                <p><strong>Discovery Method:</strong> ${{data.discovery_method}}</p>
                <p><strong>IP Addresses:</strong> ${{data.ips.join(', ')}}</p>
            `;
            
            if (data.status) {{
                html += `
                    <p><strong>HTTP Status:</strong> ${{data.status}}</p>
                    <p><strong>Title:</strong> ${{data.title || '-'}}</p>
                    <p><strong>Server:</strong> ${{data.server || '-'}}</p>
                `;
            }}
            
            if (data.open_ports && data.open_ports.length) {{
                html += `
                    <h4>Open Ports</h4>
                    <ul>
                    ${{data.open_ports.map(p => `
                        <li>Port ${{p.port}}: ${{p.service}} ${{p.banner ? `(${{p.banner}})` : ''}}</li>
                    `).join('')}}
                    </ul>
                `;
            }}
            
            if (data.takeover) {{
                html += `
                    <div class="badge badge-danger">
                        Potential Takeover Risk: ${{data.takeover.service}}
                    </div>
                    <p><em>${{data.takeover.evidence}}</em></p>
                `;
            }}
            
   
            
            content.innerHTML = html;
            modal.style.display = 'block';
        }}
        
        function closeModal() {{
            document.getElementById('detailsModal').style.display = 'none';
        }}
        
        // Close modal when clicking outside
        window.onclick = function(event) {{
            const modal = document.getElementById('detailsModal');
            if (event.target == modal) {{
                modal.style.display = 'none';
            }}
        }}
    </script>
</body>
</html>"""

        with open(outpath, 'w', encoding='utf-8') as f:
            f.write(html)
            
        logger.info(f"HTML report saved to {outpath}")
        return outpath
        
    def _generate_table_rows(self, subdomains):
        """Helper to generate HTML table rows for the report"""
        rows = []
        for i, s in enumerate(subdomains):
            status_badge = self._get_status_badge(s.get('status'))
            ports = ', '.join(str(p['port']) for p in s.get('open_ports', []))
            techs = s.get('technologies')
            if techs:
                tech_list = techs.split(',')
                tech_badges = ' '.join(f'<span class="badge badge-info">{t.strip()}</span>' 
                                    for t in tech_list if t.strip())
            else:
                tech_badges = ''
            
            row = f"""
                <tr>
                    <td>{s['domain']}</td>
                    <td>{', '.join(s.get('ips', []))}</td>
                    <td>{status_badge}</td>
                    <td>{tech_badges}</td>
                    <td>{ports}</td>
                    <td>
                        <button onclick="showDetails({i})">Details</button>
                    </td>
                </tr>
            """
            rows.append(row)
        return '\n'.join(rows)
        
    def _get_status_badge(self, status):
        """Helper to generate status badge HTML"""
        if not status:
            return '<span class="badge badge-warning">No response</span>'
            
        if status == 200:
            return f'<span class="badge badge-success">{status}</span>'
        elif status >= 500:
            return f'<span class="badge badge-danger">{status}</span>'
        else:
            return f'<span class="badge badge-warning">{status}</span>'