# SubMap

**SubMap** is an advanced subdomain enumeration and asset discovery tool designed for security professionals and penetration testers. It combines passive and active reconnaissance techniques to discover subdomains, probe services, detect vulnerabilities, and generate comprehensive reports.

## 🚀 Features

### Passive Enumeration
- **Multiple Data Sources**: Integrates with crt.sh, HackerTarget, and VirusTotal
- **Certificate Transparency**: Discovers subdomains from SSL/TLS certificates
- **DNS Record Analysis**: Comprehensive DNS resolution (A, AAAA, CNAME, MX, NS, TXT records)
- **Wildcard Detection**: Identifies domains with wildcard DNS configurations

### Active Enumeration (Optional)
- **Subdomain Bruteforce**: Efficient wordlist-based discovery with custom wordlist support
- **Recursive Discovery**: Attempts to find additional levels of subdomains
- **Port Scanning**: Identifies open ports and running services
- **Banner Grabbing**: Extracts service version information

### HTTP Analysis
- **HTTP Probing**: Tests HTTP/HTTPS connectivity with redirects
- **Status Code Detection**: Identifies working web services
- **Technology Detection**: Identifies web technologies and frameworks
- **Subdomain Takeover Detection**: Checks for vulnerable configurations

### Reporting & Storage
- **SQLite Database**: Persistent storage of all scan data
- **Multiple Export Formats**: JSON (detailed), CSV (spreadsheet), HTML (dashboard)
- **Organized Output**: Domain-specific report directories with timestamps

## 📋 Requirements

- Python 3.7+
- Internet connection (for passive enumeration)
- Authorization for the target domain (REQUIRED)

### Dependencies

```
customtkinter
Pillow
aiohttp
aiohttp-retry
dnspython
tqdm
```

## 🔧 Installation

1. **Clone the repository**:
```bash
git clone https://github.com/umyo-ukz/SubMap.git
cd SubMap
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Verify installation**:
```bash
python -m submap.cli --help
```

## 🎯 Usage

### Basic Passive Scan (Recommended for beginners)

```bash
python -m submap.cli --domain example.com --authorized
```

This performs a safe, passive-only scan using public data sources.

### Active Scan with Bruteforce

```bash
python -m submap.cli --domain example.com --authorized --active --modules bruteforce
```

### Full Scan with All Features

```bash
python -m submap.cli --domain example.com --authorized --active --modules bruteforce,portscan,recursive --tech-detect
```

### Custom Wordlist

```bash
python -m submap.cli --domain example.com --authorized --active --modules bruteforce --wordlist /path/to/wordlist.txt
```

### With VirusTotal Integration

```bash
python -m submap.cli --domain example.com --authorized --vt-api-key YOUR_VT_API_KEY
```

## 📖 Command-Line Options

### Required Arguments
- `--domain`: Target domain (e.g., example.com)
- `--authorized`: Confirmation that you have authorization (REQUIRED)

### Database Options
- `--db`: SQLite database path (default: `submap_pro.db`)

### Performance Options
- `--concurrency`: Number of concurrent tasks (default: 20)
- `--verbose, -v`: Enable verbose logging

### Active Mode Options
- `--active`: Enable active scanning (requires additional confirmation)
- `--modules`: Comma-separated list of active modules
  - `bruteforce`: Wordlist-based subdomain discovery
  - `portscan`: Port scanning on discovered hosts
  - `recursive`: Recursive subdomain enumeration
- `--wordlist`: Path to custom subdomain wordlist file

### API Integration
- `--vt-api-key`: VirusTotal API key for additional data

### Feature Flags
- `--tech-detect`: Enable web technology detection

## 🔒 Safety & Authorization

### ⚠️ IMPORTANT WARNINGS

1. **Authorization Required**: You MUST have explicit authorization to scan the target domain. Unauthorized scanning may be illegal.

2. **Active Mode Confirmation**: When using `--active` mode, you will be prompted to type `YES I AM AUTHORIZED` before the scan begins.

3. **Ethical Use**: This tool is designed for:
   - Security professionals conducting authorized assessments
   - Bug bounty hunters within program scope
   - System administrators testing their own infrastructure

## 📊 Output & Reports

All reports are saved in the `reports/` directory, organized by domain and timestamp:

```
reports/
└── example.com/
    └── scan_20250107_170000/
        ├── report.json          # Detailed scan data
        ├── subdomains.csv       # Spreadsheet format
        └── dashboard.html       # Visual dashboard
```

### Report Contents

**JSON Report**: Complete scan data including:
- Subdomain list with DNS records
- HTTP probe results
- Port scan results (if enabled)
- Takeover vulnerabilities
- Technology fingerprints

**CSV Report**: Simplified tabular format for:
- Subdomain enumeration lists
- Quick analysis in Excel/Google Sheets

**HTML Dashboard**: Interactive web interface showing:
- Summary statistics
- Subdomain overview
- Service distribution
- Vulnerability highlights

## 🎛️ Scan Phases

SubMap executes scans in organized phases:

1. **Phase 1: Passive Enumeration**
   - Queries public data sources
   - No direct contact with target

2. **Phase 2: Active Enumeration** (if enabled)
   - Wordlist bruteforcing
   - Recursive discovery

3. **Phase 3: DNS Resolution & HTTP Probing**
   - Resolves all discovered subdomains
   - Tests HTTP/HTTPS connectivity
   - Checks for takeover vulnerabilities

4. **Phase 4: Report Generation**
   - Exports data in multiple formats
   - Creates organized report directories

## 💡 Examples

### Example 1: Quick Passive Scan
```bash
python -m submap.cli --domain target.com --authorized
```

### Example 2: Comprehensive Security Assessment
```bash
python -m submap.cli \
  --domain target.com \
  --authorized \
  --active \
  --modules bruteforce,portscan,recursive \
  --wordlist wordlists/subdomains-10000.txt \
  --vt-api-key YOUR_API_KEY \
  --tech-detect \
  --concurrency 30 \
  --verbose
```

### Example 3: Bruteforce Only
```bash
python -m submap.cli \
  --domain target.com \
  --authorized \
  --active \
  --modules bruteforce \
  --wordlist custom-wordlist.txt
```

## 🗄️ Database Schema

SubMap uses SQLite to store all scan data persistently. The database includes tables for:

- Subdomains and their metadata
- DNS resolution records
- HTTP probe results
- Port scan findings
- Takeover vulnerability checks

## 🛠️ Troubleshooting

### Common Issues

**"You must pass --authorized to proceed"**
- Solution: Add the `--authorized` flag to confirm authorization

**Rate limiting or timeouts**
- Solution: Reduce `--concurrency` value (try 10-15)
- Solution: Some passive sources may have rate limits

**Port scanning hangs**
- Solution: Press CTRL+C to skip to next phase
- Solution: Reduce the number of ports or timeout values

**No results from passive sources**
- Solution: Check internet connection
- Solution: Some domains may have limited public exposure

## 🤝 Contributing

Contributions are welcome! Please ensure:
- Code follows existing style patterns
- New features include documentation
- Testing is performed before submitting

## ⚖️ Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are solely responsible for ensuring they have proper authorization before scanning any target. Unauthorized access to computer systems is illegal under various laws including the Computer Fraud and Abuse Act (CFAA) in the United States and similar laws in other jurisdictions.

The authors and contributors of SubMap:
- Do NOT endorse illegal activities
- Are NOT responsible for misuse of this tool
- Assume NO liability for damages resulting from use

**USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION**

## 📝 License

This project is available under standard open-source terms. See repository for details.

## 🔗 Resources

- **GitHub**: https://github.com/umyo-ukz/SubMap
- **Bug Reports**: Use GitHub Issues
- **Feature Requests**: Submit via GitHub

## 👤 Author

Developed by umyo-ukz

---

**Version**: 3.0  
**Last Updated**: November 2025
