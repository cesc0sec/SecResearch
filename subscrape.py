import argparse
import requests
import httpx
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import signal
import sys
import re
from urllib.parse import urlparse

# ANSI color codes
COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_BLUE = "\033[94m"
BOLD = "\033[1m"
ITALIC = "\033[3m"

ascii_art = """
            ___.                                             
  ________ _\\_ |__   ______ ________________  ______   ____  
 /  ___/  |  \\ __ \\ /  ___// ___\\_  __ \\__  \\ \\____ \\_/ __ \\ 
 \\___ \\|  |  / \\_\\ \\\\___ \\\\  \\___|  | \\// __ \\|  |_> >  ___/ 
/____  >____/|___  /____  >\\___  >__|  (____  /   __/ \\___  >
     \\/          \\/     \\/     \\/           \\/|__|        \\/                                          

"""
print(ascii_art)

def parse_args():
    parser = argparse.ArgumentParser(description="Python Subdomain Enumerator using crt.sh and httpx")
    parser.add_argument("-d", "--domains", required=True, help="Comma-separated list of domains")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-r", "--redirect", action="store_true", help="Follow redirects and print final URL")
    parser.add_argument("--regex", help="Comma-separated regex patterns to search for in headers and body")
    parser.add_argument("--cookies", action="store_true", help="Extract cookies from response")
    parser.add_argument("--title", action="store_true", help="Extract <title> from HTML")
    parser.add_argument("--emails", action="store_true", help="Preset regex to extract emails")
    parser.add_argument("--urls", action="store_true", help="Preset regex to extract URLs")
    parser.add_argument("--tokens", action="store_true", help="Preset regex to extract hex tokens")
    parser.add_argument("-p", "--paths", default="/", help="Comma-separated paths to fetch from each subdomain")
    parser.add_argument("--sm", "--show-matches", dest="show_matches", action="store_true",
                        help="Only show URLs that have matches for the regex patterns")
    return parser.parse_args()

def get_subdomains_crtsh(domain):
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=50)
        data = resp.json()
        subdomains = set()
        for entry in data:
            for name in entry['name_value'].splitlines():
                if not name.startswith("*."):
                    subdomains.add(name.strip())
        return sorted(subdomains)
    except Exception as e:
        print(f"[!] Failed to fetch subdomains for {domain}: {e}")
        return []

def is_port_open(host, port):
    try:
        with socket.create_connection((host, port), timeout=2):
            return True
    except Exception:
        return False

def colorize_status(status):
    if 200 <= status < 300:
        return f"{COLOR_GREEN}{status}{COLOR_RESET}"
    elif 300 <= status < 400:
        return f"{COLOR_YELLOW}{status}{COLOR_RESET}"
    else:
        return f"{COLOR_RED}{status}{COLOR_RESET}"

def search_regex(content, patterns):
    results = {}
    for pattern in patterns:
        try:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                results[pattern] = matches
        except re.error:
            continue
    return results

def extract_matches(r, regex_patterns, args):
    matches_dict = {}
    full_text = str(r.headers) + "\n" + r.text

    if args.regex:
        matches_dict.update(search_regex(full_text, regex_patterns))

    if args.cookies and r.cookies:
        cookie_matches = [f"{name}={value}" for name, value in r.cookies.items()]
        if cookie_matches:
            matches_dict["Cookies"] = cookie_matches

    if args.title:
        title_match = re.findall(r"<title[^>]*>(.*?)</title>", r.text, re.IGNORECASE | re.DOTALL)
        if title_match:
            matches_dict["Title"] = title_match

    if args.emails:
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", full_text, re.IGNORECASE)
        if emails:
            matches_dict["Emails"] = emails

    if args.urls:
        urls = re.findall(r"https?://[^\s'\"<>]+", full_text, re.IGNORECASE)
        if urls:
            matches_dict["URLs"] = urls

    if args.tokens:
        pattern = r"\b[a-f0-9]{32}\b|\b[a-f0-9]{64}\b|\b[a-f0-9]{128}\b|\b[a-f0-9]{256}\b|\b[a-f0-9]{512}\b"
        tokens = re.findall(pattern, full_text, re.IGNORECASE)
        if tokens:
            matches_dict["Tokens"] = tokens
  
    return matches_dict

def probe(subdomain, paths, follow_redirects, regex_patterns, args):
    results = []
    try:
        if len(subdomain) > 253 or any(len(part) > 63 for part in subdomain.split(".")):
            return []
        socket.gethostbyname(subdomain)
    except (socket.gaierror, UnicodeEncodeError):
        return []

    for path in paths:
        path = "/" + path.strip().lstrip("/")

        checked_https = False
        if is_port_open(subdomain, 443):
            url = f"https://{subdomain}{path}"
            try:
                r = httpx.get(url, timeout=5.0, verify=False, follow_redirects=follow_redirects)
                final_url = str(r.url)
                result_url = final_url if follow_redirects else url

                matches_dict = extract_matches(r, regex_patterns, args)

                if not args.show_matches or (args.show_matches and matches_dict):
                    result = (result_url, r.status_code)
                    if matches_dict:
                        result += (matches_dict,)
                    results.append(result)
                checked_https = True
            except httpx.RequestError:
                pass

        if is_port_open(subdomain, 80):
            url = f"http://{subdomain}{path}"
            try:
                r = httpx.get(url, timeout=5.0, verify=False, follow_redirects=follow_redirects)
                final_url = str(r.url)
                result_url = final_url if follow_redirects else url
                if final_url.startswith("https://") and checked_https:
                    continue

                matches_dict = extract_matches(r, regex_patterns, args)

                if not args.show_matches or (args.show_matches and matches_dict):
                    result = (result_url, r.status_code)
                    if matches_dict:
                        result += (matches_dict,)
                    results.append(result)
            except httpx.RequestError:
                pass

    return results

def handle_interrupt(signum, frame):
    print("\n[!] Exiting...")
    sys.exit(0)

def main():
    signal.signal(signal.SIGINT, handle_interrupt)
    args = parse_args()
    domains = [d.strip() for d in args.domains.split(",")]
    threads = args.threads
    follow_redirects = args.redirect
    paths = [p.strip() for p in args.paths.split(",") if p.strip()]

    regex_patterns = []
    if args.regex:
        regex_patterns.extend([p.strip() for p in args.regex.split(",") if p.strip()])

    all_subdomains = []
    for domain in domains:
        subs = get_subdomains_crtsh(domain)
        print(f"[+] {domain}: {len(subs)} subdomains found")
        all_subdomains.extend(subs)

    if not all_subdomains:
        print("[!] No subdomains to probe. Exiting.")
        return

    print(f"\n[+] Probing {len(all_subdomains)} subdomains with {threads} threads...\n")

    seen = set()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(probe, sub, paths, follow_redirects, regex_patterns, args): sub
            for sub in all_subdomains
        }
        for future in as_completed(futures):
            for result in future.result():
                url, status = result[:2]
                if url not in seen:
                    seen.add(url)
                    output = f"{BOLD}{url}{COLOR_RESET} => {colorize_status(status)}"
                    if len(result) == 3:
                        matches_dict = result[2]
                        print(output)
                        for label, matches in matches_dict.items():
                            print(f"| {COLOR_BLUE}{label}{COLOR_RESET} |")
                            for m in set(matches):
                                print(f"| {ITALIC}{m}{COLOR_RESET} |")
                    else:
                        print(output)

if __name__ == "__main__":
    main()
