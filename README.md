# SubScrape

**SubScrape** is a Python tool for discovering subdomains and probing HTTP/HTTPS endpoints, using crt.sh for subdomain enumeration and httpx for fast, concurrent probing. It extracts data such as emails, URLs, hex tokens, cookies, titles, with customizable regex matching.

### Features

- Subdomain discovery via crt.sh
- Concurrent probing with thread support
- Extract emails, URLs, tokens, cookies, titles
- Custom regex matching

### Usage
```bash
python subscrape.py --help
            ___.                                             
  ________ _\_ |__   ______ ________________  ______   ____  
 /  ___/  |  \ __ \ /  ___// ___\_  __ \__  \ \____ \_/ __ \ 
 \___ \|  |  / \_\ \\___ \\  \___|  | \// __ \|  |_> >  ___/ 
/____  >____/|___  /____  >\___  >__|  (____  /   __/ \___  >
     \/          \/     \/     \/           \/|__|        \/                                          


usage: subscrape.py [-h] -d DOMAINS [-t THREADS] [-r] [--regex REGEX] [--cookies] [--title] [--emails] [--urls]
                    [--tokens] [-p PATHS] [--sm]

Python Subdomain Enumerator using crt.sh and httpx

options:
  -h, --help            show this help message and exit
  -d, --domains DOMAINS
                        Comma-separated list of domains
  -t, --threads THREADS
                        Number of threads (default: 10)
  -r, --redirect        Follow redirects and print final URL
  --regex REGEX         Comma-separated regex patterns to search for in headers and body
  --cookies             Extract cookies from response
  --title               Extract <title> from HTML
  --emails              Preset regex to extract emails
  --urls                Preset regex to extract URLs
  --tokens              Preset regex to extract hex tokens
  -p, --paths PATHS     Comma-separated paths to fetch from each subdomain
  --sm, --show-matches  Only show URLs that have matches for the regex patterns

 ```

### Example
```bash
python subscrape.py -d github.com --sm -p "/,login,admin" --emails --cookies --regex "api_key=\w+"
```

### Install

```bash
git clone https://github.com/cesc0sec/Subscraper.git
cd Subscraper/
pip install requirements.txt
