import argparse
import httpx
import threading
import sys

def parse_headers(header_list):
    headers = {}
    for h in header_list:
        if ':' in h:
            key, value = h.split(':', 1)
            headers[key.strip()] = value.strip()
        else:
            print(f"Invalid header format: {h}", file=sys.stderr)
    return headers

def send_request(index, method, url, headers):
    try:
        with httpx.Client(http2=True, timeout=10) as client:
            response = client.request(method, url, headers=headers)
            print(f"[{index}] Status: {response.status_code}")
    except Exception as e:
        print(f"[{index}] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Race condition tester with HTTP/2 support")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-X", "--method", default="GET", help="HTTP method (GET, POST, etc.)")
    parser.add_argument("-H", "--header", action="append", default=[], help="Custom headers")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of parallel threads")

    args = parser.parse_args()

    headers = parse_headers(args.header)
    threads = []

    for i in range(args.threads):
        thread = threading.Thread(target=send_request, args=(i, args.method.upper(), args.url, headers))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == "__main__":
    main()
