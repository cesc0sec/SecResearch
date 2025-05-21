# Tools Collection

This repository contains several small utility tools.

## Included Tools

### CSRF Form Generator (`csrf_formgen.py`)

A Python utility to convert raw HTTP POST requests into HTML forms for CSRF testing.

---

### Features

- Supports `application/x-www-form-urlencoded` and `multipart/form-data` POST requests.
- Converts multipart data into hidden HTML inputs.
- Reads raw HTTP request from a file or standard input.
- Output filename customizable (default: `csrf.html`).

---

### Usage

```bash
python3 csrf_formgen.py -f path/to/request.txt -o output.html
