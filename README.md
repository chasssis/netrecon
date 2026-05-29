# NetRecon

A network reconnaissance and vulnerability scanning web application built with Python and Flask. Designed for authorized security assessments, penetration testing labs, and cybersecurity education.

## Features

| Module | Description |
|--------|-------------|
| **IP Information** | Resolves the target to an IP and fetches geolocation, ASN, ISP, and timezone via ipapi.co |
| **Port Scanner** | Multi-threaded TCP connect scan across 75 ports with protocol-aware banner grabbing and risk annotations |
| **HTTP Header Analyzer** | Fetches and grades HTTP security headers with an A–F score |
| **WHOIS Lookup** | Retrieves domain registration data — registrar, creation/expiry dates, nameservers |
| **DNS Enumeration** | Queries A, AAAA, MX, NS, TXT, and CNAME records; detects SPF/DMARC and probes 13 common DKIM selectors |
| **SSL/TLS Inspector** | Validates certificates, checks expiry, protocol version (TLS 1.2+), and SANs |

- Clean terminal-aesthetic web dashboard
- Non-blocking background scan jobs with live progress updates
- Export scan results as JSON with one click
- Input validation — blocks private IPs, localhost, and malformed targets
- Rate limiting — prevents abuse of the scan API
- Structured logging via Python's `logging` module
- Protocol-aware banner grabbing (HTTP GET on web ports for richer server info)
- Modular architecture — add new scan modules easily
- Ethical use disclaimer and responsible design

---

## Demo

```
Target: scanme.nmap.org
Modules: Port Scan, HTTP Headers, DNS, WHOIS

[*] Running Port Scan...
[+] Port Scan complete.
[*] Running WHOIS Lookup...
[+] WHOIS complete.
...
[✓] Scan finished.
```

---

## Installation

### Prerequisites
- Python 3.10+
- pip

### Local Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/netrecon.git
cd netrecon

# Create a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the app
python app.py
```

Open your browser at `http://localhost:5000`

The app runs in production mode by default. To enable Flask's debug mode locally:

```bash
FLASK_DEBUG=true python app.py
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up --build
```

Or with plain Docker:

```bash
docker build -t netrecon .
docker run -p 5000:5000 netrecon
```

---

## Usage

1. Enter a target hostname or IP address (e.g. `scanme.nmap.org`)
2. Select which scan modules to run
3. Click **Execute Scan**
4. Results populate in real time as each module completes
5. Click **Export JSON** to download the full results as a `.json` file

> **Important:** Only scan systems you own or have explicit permission to test.
> Unauthorized scanning may violate the Computer Fraud and Abuse Act (CFAA) and similar laws.

### Input Validation

NetRecon enforces the following rules on every scan target before a job starts:

- Private IP ranges (`10.x.x.x`, `172.16–31.x.x`, `192.168.x.x`) are blocked
- Loopback addresses (`127.x.x.x`, `localhost`) are blocked
- Targets with invalid characters are rejected
- Empty targets return an immediate error

### Rate Limiting

The `/api/scan` endpoint is rate-limited per IP:

| Window | Limit |
|--------|-------|
| Per minute | 10 requests |
| Per hour | 50 requests |
| Per day | 200 requests |

---

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run the full test suite
pytest tests/ -v
```

The test suite covers:

- `normalize_target` — URL stripping and hostname extraction
- `validate_target` — private IP blocking, localhost rejection, character validation
- `_ssl_warnings` — certificate expiry and deprecated protocol detection
- `ReconScanner` initialization
- Port scanner result structure and total count (mocked sockets)
- HTTP header grading thresholds (A–F)
- Module constants sanity checks (port ranges, header names)

---

## Project Structure

```
netrecon/
├── app.py                  # Flask application, job management, rate limiting
├── modules/
│   ├── __init__.py
│   └── scanner.py          # Core scan modules + input validation
├── templates/
│   └── index.html          # Frontend dashboard
├── tests/
│   ├── __init__.py
│   └── test_scanner.py     # pytest unit tests (50 tests)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt        # Production dependencies
├── requirements-dev.txt    # Dev/test dependencies
├── .gitignore
└── README.md
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FLASK_DEBUG` | `false` | Enable Flask debug mode (`true`/`false`) |
| `PORT` | `5000` | Port the server listens on |

---

## Extending NetRecon

Adding a new scan module takes three steps:

**1. Add a method to `ReconScanner` in `modules/scanner.py`:**
```python
def my_new_scan(self) -> dict:
    logger.debug("My scan starting: target=%s", self.target)
    # your logic here
    return {"result": "data"}
```

**2. Register it in `run_scan_job` in `app.py`:**
```python
if "my_scan" in scan_types:
    steps.append(("my_scan", "My Scan Label", scanner.my_new_scan))
```

**3. Add a checkbox to the form in `index.html` and a card renderer in JavaScript.**

---

## Security Considerations

- **Thread pool** is capped to avoid flooding the target with connections
- **Input validation** blocks private/loopback addresses before any scan begins
- **Rate limiting** prevents the API from being abused as an open scanning proxy
- **Debug mode** is off by default; enable explicitly via `FLASK_DEBUG=true`
- **SSL verification** is attempted first; falls back to HTTP if HTTPS fails
- **No persistence** — scan results are stored in memory only and lost on server restart

---

## Technologies Used

- **Flask** — lightweight Python web framework
- **Flask-Limiter** — API rate limiting
- **Python `logging`** — structured application logging
- **Python `socket`** — raw TCP connect scanning and banner grabbing
- **`concurrent.futures`** — 100-worker thread pool for parallel port scanning
- **`dnspython`** — DNS record resolution and DKIM selector probing
- **`python-whois`** — WHOIS lookups
- **`requests`** — HTTP header fetching and IP geolocation
- **`ssl`** — certificate inspection
- **`ipaddress`** — private IP range validation
- **ipapi.co** — free IP geolocation and ASN API (no key required)
- **pytest** — unit testing
- **gunicorn** — production WSGI server (used in Docker)
- Vanilla JS + CSS — no frontend frameworks

---

## Legal Disclaimer

This tool is intended for **educational purposes and authorized security testing only**.
The author assumes no liability for misuse. Always obtain written permission before scanning any system you do not own.

---

## License

MIT — see [LICENSE](LICENSE) for details.
