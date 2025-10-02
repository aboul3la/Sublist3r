# Sublist3r ![Python](https://img.shields.io/badge/Python-3.6%2B-blue?logo=python&logoColor=white) [![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-green.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html) [![Stars](https://img.shields.io/github/stars/aboul3la/Sublist3r?style=social)](https://github.com/aboul3la/Sublist3r/stargazers)

> **Sublist3r** is a fast and powerful Python tool designed for OSINT-based subdomain enumeration. It helps penetration testers, bug bounty hunters, and security researchers discover hidden subdomains for targeted domains. Sublist3r leverages multiple search engines (Google, Yahoo, Bing, Baidu, Ask) and passive sources (Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, ReverseDNS, BufferOverRun, CertSpotter) to build comprehensive subdomain lists.

**Enhanced to v3.0 by [Shaheer Yasir](https://github.com/shaheeryasir) (2025):** Full Python 3 support, new passive engines (CertSpotter for Certificate Transparency logs, BufferOverRun for DNS intel), JSON output, improved performance, and VirusTotal API v3 integration.

## 🚀 Features
- **Multi-Engine Enumeration:** Supports 12+ search engines and passive sources for broad coverage.
- **Brute-Force Integration:** Powered by [SubBrute](https://github.com/TheRook/subbrute) (v1.3) with optimized wordlists.
- **Output Flexibility:** Text or JSON export; verbose real-time results.
- **Port Scanning:** Built-in TCP port checks on discovered subdomains.
- **Modular Design:** Easy to import as a Python library.
- **Cross-Platform:** Works on Linux, macOS, and Windows (with colorama for enhanced output).
- **Rate-Limited & Stealthy:** Configurable threads, sleeps, and proxies to avoid detection.

## 📦 Installation

1. **Clone the Repository:**
   ```
   git clone https://github.com/aboul3la/Sublist3r.git
   cd Sublist3r
   ```

2. **Install Dependencies:**
   ```
   pip install -r requirements.txt
   ```
   (Includes `requests>=2.25.0`, `dnspython>=2.0.0`, `colorama>=0.4.4`)

3. **Optional: VirusTotal API Key:**
   For unlimited scans, set `export VT_API_KEY=your_key_here`.

> **Note:** Python 3.6+ required (tested up to 3.12). No Python 2 support.

## 🔧 Usage

| Short Form | Long Form       | Description |
|------------|-----------------|-------------|
| `-d`      | `--domain`      | Domain name to enumerate subdomains of |
| `-b`      | `--bruteforce`  | Enable the SubBrute bruteforce module |
| `-p`      | `--ports`       | Scan found subdomains against specific TCP ports |
| `-v`      | `--verbose`     | Enable verbose mode and display results in realtime |
| `-t`      | `--threads`     | Number of threads for SubBrute bruteforce (default: 30) |
| `-e`      | `--engines`     | Comma-separated list of search engines |
| `-o`      | `--output`      | Save results to text file |
| `-j`      | `--json`        | Save results to JSON file |
| `-n`      | `--no-color`    | Output without color |
| `-h`      | `--help`        | Show the help message and exit |

### Examples

* **Basic Enumeration:**
  ```
  python sublist3r.py -d example.com
  ```

* **With Port Scanning (80, 443):**
  ```
  python sublist3r.py -d example.com -p 80,443
  ```

* **Verbose Real-Time Results:**
  ```
  python sublist3r.py -v -d example.com
  ```

* **Enable Bruteforce:**
  ```
  python sublist3r.py -b -d example.com
  ```

* **Specific Engines (Google, Yahoo, VirusTotal):**
  ```
  python sublist3r.py -e google,yahoo,virustotal -d example.com
  ```

* **Full Scan with JSON Output:**
  ```
  python sublist3r.py -d example.com -b -v -j -o output.txt
  ```

## 📚 Using Sublist3r as a Module

Import Sublist3r into your Python scripts for automated workflows.

```python
import sublist3r

# Enumerate subdomains
subdomains = sublist3r.main(
    domain='yahoo.com',
    no_threads=40,          # Threads for bruteforce
    savefile='yahoo_subdomains.txt',  # Output file
    ports=None,             # Ports to scan
    silent=False,           # Silent mode
    verbose=False,          # Real-time output
    enable_bruteforce=False, # Enable bruteforce
    engines=None            # Specific engines
)

print(f"Found {len(subdomains)} subdomains: {subdomains}")
```

**Parameters:**
- `domain`: Target domain.
- `savefile`: Optional output file.
- `ports`: Comma-separated TCP ports.
- `silent`: Suppress noise.
- `verbose`: Real-time display.
- `enable_bruteforce`: Use SubBrute.
- `engines`: Optional comma-separated engines (e.g., 'google,bing').

## 🖼️ Screenshots

![Sublist3r in Action](http://www.secgeek.net/images/Sublist3r.png)

## 🤝 Credits

- **[Ahmed Aboul-Ela](https://twitter.com/aboul3la)**: Original author.
- **[TheRook](https://github.com/TheRook)**: SubBrute bruteforce module.
- **[Bitquark](https://github.com/bitquark)**: SubBrute wordlist based on **dnspop** research.
- **[Shaheer Yasir](https://github.com/shaheeryasir)**: v3.0 enhancements (Python 3, new engines, JSON output, performance).
- **Special Thanks:** [Ibrahim Mosaad](https://twitter.com/ibrahim_mosaad) for foundational contributions.

## 📄 License

Sublist3r is licensed under the [GNU GPL v2](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html). See [LICENSE](LICENSE) for details.

## 🙌 Contributing

We welcome contributions! Fork the repo, create a feature branch, and submit a PR. For issues or questions, open a ticket on GitHub.

- Report bugs: [Issues](https://github.com/aboul3la/Sublist3r/issues)
- Suggest features: [Discussions](https://github.com/aboul3la/Sublist3r/discussions)

## 📈 Version

**Current version: 3.0** (October 01, 2025)

---

⭐ **Star this repo** if Sublist3r helps your recon workflow! Follow [@aboul3la](https://twitter.com/aboul3la) for updates. Happy hunting! 🔍
























































