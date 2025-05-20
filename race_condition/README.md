# Race Condition Tester

This script is designed to test for race condition vulnerabilities by sending multiple concurrent HTTP/2 requests to a target endpoint.

## 🚀 Features

- Supports **HTTP/2** for modern web targets.
- Send requests in **parallel** using threads.
- Customize:
  - URL
  - HTTP method (`GET`, `POST`, `PUT`, etc.)
  - Headers
  - Number of threads

## 🛠️ Requirements

- Python 3.7+
- Dependencies listed in [`requirements.txt`](./requirements.txt)

Install with:

```bash
pip install -r requirements.txt
```

## Usage

python3 racecon.py -u <url> -X <method> -H "Header: value" -t <threads>

## Example

python3 racecon.py -u https://example.com/api/claim -X POST -H "Content-Type: application/json" -H "Cookie: session=abc123" -t 100

## Notes

- Outputs only the status code for each request.
- Designed to help identify race conditions in claim/redeem endpoints or logic flaw scenarios.

## Disclaimer

This tool is for authorized testing and educational use only. Do not use it against systems you do not own or have permission to test.

## 👤 Author

Security research by [cesc0sec](https://github.com/cesc0sec)
