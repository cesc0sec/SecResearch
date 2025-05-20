# Race Condition Tester

This script is designed to test for race condition vulnerabilities by sending multiple concurrent requests to a target endpoint.

## 🚀 Features

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

python racecon.py [-h] -u URL [-X METHOD] [-H HEADER] [-t THREADS]

## Example

python racecon.py -u https://example.com/api/claim -X POST -H "Content-Type: application/json" -H "Cookie: session=abc123" -t 100

## Disclaimer

This tool is for authorized testing and educational use only. Do not use it against systems you do not own or have permission to test.

## 👤 Author

Security research by [cesc0sec](https://github.com/cesc0sec)
