#!/usr/bin/env python3
"""
Subdomain Takeover Extension for Sublist3r v3.0 - Fixed & improved

Usage examples:
  python takeover_extension_fixed.py -i subdomains.txt -o results.txt --delay 0.2 -t 20 -v
  cat subdomains.txt | python takeover_extension_fixed.py -o results.txt

Requirements:
  pip install dnspython requests colorama
"""
import argparse
import sys
import time
import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.exception
import threading

# Silence TLS warnings (we use verify=False on purpose for dangling domains)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Console Colors (using colorama for cross-platform)
try:
    import colorama
    colorama.init(autoreset=True)
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'   # white
except Exception:
    G = Y = B = R = W = ''

# Lock for thread-safe prints and writes
LOCK = threading.Lock()

def banner():
    print(f"""{R}
    ╔══════════════════════════════════════════════════════════════╗
    ║  Subdomain Takeover Extension for Sublist3r v3.0             ║
    ║  Detects dangling CNAMEs & HTTP fingerprints                 ║
    ║  Provides evidence snippets and confidence levels            ║
    ╚══════════════════════════════════════════════════════════════╝{W}{Y}
    """)

# --- Fingerprints ---
FINGERPRINTS = {
    "GitHub Pages": {
        "cname_suffix": "github.io",
        "keywords": ["There isn't a GitHub Pages site here."],
        "nxdomain_required": False
    },
    "Heroku": {
        "cname_suffix": "herokuapp.com",
        "keywords": ["No such app"],
        "nxdomain_required": False
    },
    "AWS/S3": {
        "cname_suffix": "s3.amazonaws.com",
        "keywords": ["The specified bucket does not exist"],
        "nxdomain_required": False
    },
    "Shopify": {
        "cname_suffix": "myshopify.com",
        "keywords": ["Sorry, this shop is currently unavailable"],
        "nxdomain_required": False
    },
    # Example keyword-only fingerprint
    "Canny": {
        "cname_suffix": None,
        "keywords": ["Company Not Found", "There is no such company"],
        "nxdomain_required": False
    }
}

# --- DNS helpers ---
def resolve_cname(subdomain):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(subdomain, 'CNAME')
        return [r.target.to_text().rstrip('.') for r in answers]
    except dns.resolver.NXDOMAIN:
        return ["NXDOMAIN"]
    except (dns.resolver.NoAnswer, dns.exception.DNSException):
        return []
    return []

def resolve_a(name):
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(name, 'A')
        return [r.address for r in answers]
    except Exception:
        return []

def is_dangling_cname(target):
    if target == "NXDOMAIN":
        return True
    ips = resolve_a(target)
    return len(ips) == 0

# --- HTTP fingerprinting ---
def check_http_fingerprint(subdomain, keywords, verbose=False):
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}/"
        try:
            resp = requests.get(url, timeout=6, verify=False, allow_redirects=True)
        except requests.RequestException as e:
            if verbose:
                with LOCK:
                    print(f"{Y}[!] HTTP error {url}: {e}{W}")
            continue
        body = resp.text or ""
        for kw in keywords:
            if kw in body:
                snippet = body[body.find(kw)-50:body.find(kw)+50].replace("\n", " ")
                return True, kw, url, resp.status_code, snippet
    return False, None, None, None, None

# --- Takeover analysis ---
def check_takeover(subdomain, verbose=False):
    cnames = resolve_cname(subdomain)
    a_records = resolve_a(subdomain)

    # NXDOMAIN handling
    if "NXDOMAIN" in cnames and not a_records:
        suspects = []
        for svc, fp in FINGERPRINTS.items():
            if fp.get("nxdomain_required"):
                suspects.append(svc)
        if suspects:
            return {
                "vulnerable": True,
                "service": ", ".join(suspects),
                "confidence": "low",
                "evidence": {"dns": "NXDOMAIN"},
                "note": "NXDOMAIN detected, manual validation needed."
            }

    # Check CNAME-based providers
    for cname in cnames:
        for svc, fp in FINGERPRINTS.items():
            suffix = fp.get("cname_suffix")
            if suffix and cname.lower().endswith(suffix.lower()):
                dangling = is_dangling_cname(cname)
                matched, kw, url, status, snippet = check_http_fingerprint(subdomain, fp["keywords"], verbose)
                if dangling and matched:
                    return {
                        "vulnerable": True, "service": svc, "confidence": "high",
                        "evidence": {"cname": cname, "http_url": url, "status": status, "kw": kw, "snippet": snippet},
                        "note": "Dangling CNAME + HTTP fingerprint match"
                    }
                if dangling:
                    return {
                        "vulnerable": True, "service": svc, "confidence": "medium",
                        "evidence": {"cname": cname}, "note": "Dangling CNAME, no HTTP fingerprint"
                    }
                if matched:
                    return {
                        "vulnerable": True, "service": svc, "confidence": "medium",
                        "evidence": {"http_url": url, "status": status, "kw": kw, "snippet": snippet},
                        "note": "HTTP fingerprint matched but CNAME resolves"
                    }

    # Keyword-only providers
    for svc, fp in FINGERPRINTS.items():
        if fp["cname_suffix"] is None:
            matched, kw, url, status, snippet = check_http_fingerprint(subdomain, fp["keywords"], verbose)
            if matched:
                return {
                    "vulnerable": True, "service": svc, "confidence": "high",
                    "evidence": {"http_url": url, "status": status, "kw": kw, "snippet": snippet},
                    "note": "Keyword-only fingerprint matched"
                }

    return {"vulnerable": False}

# --- Processing ---
def process_subdomain(sub, verbose=False, output_file=None):
    with LOCK:
        print(f"{B}[*] Checking {sub}{W}")
    result = check_takeover(sub, verbose)
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    if result["vulnerable"]:
        line = f"[!] {ts} {sub} VULNERABLE ({result['service']}) | Confidence: {result['confidence']} | Evidence: {result['evidence']} | Note: {result['note']}"
        with LOCK:
            print(f"{R}{line}{W}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(line + "\n")
    else:
        line = f"[+] {ts} {sub} not vulnerable"
        with LOCK:
            print(f"{G}{line}{W}")
        if output_file:
            with open(output_file, "a") as f:
                f.write(line + "\n")

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Subdomain Takeover Extension for Sublist3r")
    parser.add_argument("-i", "--input", help="Input file of subdomains")
    parser.add_argument("-o", "--output", help="Output file")
    parser.add_argument("-d", "--domain", help="Domain (demo mode with test/dev/staging)")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between results")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrent threads")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose debug")
    args = parser.parse_args()

    banner()
    subs = []
    if args.domain:
        subs = [f"test.{args.domain}", f"dev.{args.domain}", f"staging.{args.domain}"]
    elif args.input:
        with open(args.input) as f:
            subs = [x.strip() for x in f if x.strip()]
    else:
        subs = [x.strip() for x in sys.stdin if x.strip()]

    if not subs:
        print(f"{R}[!] No subdomains provided{W}")
        sys.exit(1)

    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        futures = [exe.submit(process_subdomain, s, args.verbose, args.output) for s in subs]
        for f in as_completed(futures):
            if args.delay > 0:
                time.sleep(args.delay)

    print(f"{G}[+] Scan complete{W}")

if __name__ == "__main__":
    main()
