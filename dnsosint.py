#!/usr/bin/env python3
import socket, subprocess, urllib.request, json, ssl, re, sys
from html.parser import HTMLParser
import signal

# ─── Styling ─────────────────────────────────────────────────────────────
def color(text, c): return f"\033[{c}m{text}\033[0m"
def blue(t): return color(t, "94")
def green(t): return color(t, "92")
def yellow(t): return color(t, "93")
def red(t): return color(t, "91")
def bold(t): return color(t, "1")

# ─── Graceful CTRL+C ──────────────────────────────────────────────────────
def handler(sig, frame):
    print(red("\n[!] Aborted by user"))
    sys.exit(0)
signal.signal(signal.SIGINT, handler)

# ─── ASCII Banner ─────────────────────────────────────────────────────────
def banner():
    print(bold(red("""
▓█████▄  ███▄    █   ██████  ▒█████    ██████  ██▓ ███▄    █ ▄▄▄█████▓
▒██▀ ██▌ ██ ▀█   █ ▒██    ▒ ▒██▒  ██▒▒██    ▒ ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒
░██   █▌▓██  ▀█ ██▒░ ▓██▄   ▒██░  ██▒░ ▓██▄   ▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░
░▓█▄   ▌▓██▒  ▐▌██▒  ▒   ██▒▒██   ██░  ▒   ██▒░██░▓██▒  ▐▌██▒░ ▓██▓ ░ 
░▒████▓ ▒██░   ▓██░▒██████▒▒░ ████▓▒░▒██████▒▒░██░▒██░   ▓██░  ▒██▒ ░ 
 ▒▒▓  ▒ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░░▓  ░ ▒░   ▒ ▒   ▒ ░░   
 ░ ▒  ▒ ░ ░░   ░ ▒░░ ░▒  ░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░ ▒ ░░ ░░   ░ ▒░    ░    
 ░ ░  ░    ░   ░ ░ ░  ░  ░  ░ ░ ░ ▒  ░  ░  ░   ▒ ░   ░   ░ ░   ░      
   ░             ░       ░      ░ ░        ░   ░           ░         
 ░                                                                    
                            by DelorianCS
""")))

# ─── HTML Title Parser ────────────────────────────────────────────────────
class TitleParser(HTMLParser):
    def __init__(self): super().__init__(); self.title = ""; self.in_title = False
    def handle_starttag(self, tag, attrs): self.in_title = tag == "title"
    def handle_data(self, data): 
        if self.in_title: self.title += data
    def handle_endtag(self, tag): 
        if tag == "title": self.in_title = False
def extract_title(html):
    parser = TitleParser()
    parser.feed(html)
    return parser.title.strip() if parser.title else "N/A"

# ─── Data Source ──────────────────────────────────────────────────────────
def fetch_crtsh(domain):
    print(blue("[~] Fetching from crt.sh..."))
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(url, context=ctx) as r:
            data = json.loads(r.read().decode())
        entries = [d['name_value'].split("\n") for d in data]
        flat = [item.strip() for sublist in entries for item in sublist if domain in item]
        return sorted(set(flat))
    except Exception as e:
        print(red(f"[!] crt.sh error: {e}"))
        return []

# ─── Utilities ────────────────────────────────────────────────────────────
def resolve(subs):
    ip_map = {}
    for s in subs:
        try: ip_map[s] = socket.gethostbyname(s)
        except: continue
    return ip_map

def reverse_dns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return "N/A"

def get_title(domain):
    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(f"http://{domain}", timeout=2, context=ctx) as r:
            html = r.read().decode(errors="ignore")
            return extract_title(html)
    except: return "N/A"

def dig(domain, rtype):
    try:
        out = subprocess.check_output(["dig", "+short", domain, rtype], stderr=subprocess.DEVNULL)
        return [x.strip() for x in out.decode().split("\n") if x.strip()]
    except: return []

# ─── Recon ────────────────────────────────────────────────────────────────
def passive_recon(domain):
    print(bold(green(f"\n[+] Starting passive recon for: {domain}\n")))
    subs = fetch_crtsh(domain)
    print(green(f"[+] Total unique subdomains found: {len(subs)}"))

    print(bold(blue("\n[~] All subdomains:")))
    for sub in subs:
        print(f" - {yellow(sub)}")

    print(blue("\n[~] Resolving subdomains..."))
    resolved = resolve(subs)
    print(green(f"[+] Resolved {len(resolved)} IPs"))

    print(bold(blue("\n[+] Subdomains (with IP, Reverse DNS, and Title):\n")))
    print(f"{'Subdomain':<60} {'IP':<35} {'Reverse DNS':<70} {'Title'}")
    print("=" * 180)
    for sub in subs:
        ip = resolved.get(sub, "N/A")
        rev = reverse_dns(ip) if ip != "N/A" else "N/A"
        title = get_title(sub) if ip != "N/A" else "N/A"
        print(f"{yellow(sub):<60} {green(ip):<35} {blue(rev):<70} {title}")

    print(bold(blue("\n[+] MX Records:")))
    for r in dig(domain, "MX"): print(f" - {r}")

    print(bold(blue("\n[+] NS Records:")))
    for r in dig(domain, "NS"): print(f" - {r}")

    print(bold(blue("\n[+] TXT Records:")))
    for r in dig(domain, "TXT"): print(f" - {r}")

    print(green(bold("\n[✓] Recon finished")))

    print(bold(blue("\n[+] Suggested Google Dorks:")))
    dorks = [
        f'site:{domain}',
        f'site:*.*.{domain}',
        f'inurl:{domain} ext:php | ext:asp | ext:aspx',
        f'intext:{domain}',
        f'"index of" {domain}',
        f'"login" site:{domain}',
        f'"password" site:{domain}',
    ]
    for d in dorks:
        print(f" - {d}")

# ─── Entry Point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(red("Usage: python3 dnsosint.py <domain>"))
        sys.exit(1)
    banner()
    passive_recon(sys.argv[1])
