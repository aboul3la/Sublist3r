# Sublist3r (fork by Mazen Nafee)

**Fork of** aboul3la/Sublist3r — maintained by Mazen Nafee.  
This fork focuses on robustness, tests, and developer ergonomics:

- Defensive DNSdumpster CSRF extraction (regex + BeautifulSoup fallback).  
- Validation and safe handling of nameserver entries to avoid dnspython errors.  
- Unit tests and small repro scripts for the fixes.  
- GitHub Actions CI to run tests on push and pull requests.

---

## About

Sublist3r is a Python tool for enumerating subdomains using OSINT. It helps penetration testers and bug hunters collect subdomains for a target domain by querying search engines and public services. Sublist3r supports multiple sources including Google, Yahoo, Bing, Baidu, Ask, Netcraft, VirusTotal, ThreatCrowd, DNSdumpster, and ReverseDNS.

Subbrute is integrated to increase coverage via bruteforce using an improved wordlist. Credit for subbrute goes to TheRook.

---

## Quick start

```bash
# clone the fork
git clone https://github.com/mazennafee/Sublist3r.git
cd Sublist3r

# create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate

# install editable and test dependencies
pip install --upgrade pip
pip install -e .
pip install -r requirements.txt || true

# run tests
pytest -q

