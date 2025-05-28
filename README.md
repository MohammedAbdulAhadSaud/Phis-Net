# Phis-Net -A Phishing Link Scanner
PHISH-NET is a Python-based URL analysis tool designed to help detect potentially phishing or suspicious URLs by performing multiple checks, including URL keyword inspection, HTTP redirect tracing, WHOIS domain info retrieval, DNS record lookup, and SSL certificate presence.

---

## Features

- Detects suspicious keywords in URLs (e.g., login, verify, secure, account).
- Follows redirects and shows the full redirect chain.
- Fetches WHOIS info like domain creation and expiration dates.
- Checks DNS records (A, AAAA, NS, MX) to detect anomalies.
- Verifies if the URL uses HTTPS or if SSL is missing.
- Flags URLs as suspicious or safe with detailed explanations.
- Colorful terminal output for easy reading.

---

## Installation

Make sure you have Python 3 installed. Then install the required Python packages:

```bash
pip install requests python-whois dnspython colorama pyfiglet
