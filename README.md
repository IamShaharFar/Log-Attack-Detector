# Log Attack Detector 🐍

A Python CLI tool for automatically detecting potential cyber attacks and suspicious activity in web server log files (Apache/Nginx).  
Designed for both learning and real-world demonstration of security research and threat detection.

---

## Features

- **Brute-force detection**: Identify repeated failed login attempts from same IP.
- **SQL Injection detection**: Detect URLs containing SQLi patterns.
- **Sensitive paths detection**: Alerts on access to sensitive URLs (e.g. /admin, /.env).
- **Scan/Rate-limit detection**: Finds IPs making excessive requests in a short time.
- **Suspicious User-Agent**: Flags requests using common attack tools (sqlmap, curl, nikto).
- **Flexible filters**: By IP, URL substring, HTTP method, attack type, and result limit.
- **Clear CLI report**: Summary table with all findings, print or save to file.

---

## Usage

```bash
python log_attack_detector.py --logfile <logfile> [OPTIONS]
```

### Examples

- **Detect everything in the log:**
  ```bash
  python log_attack_detector.py --logfile test.log
  ```
- **Only for a specific IP:**
  ```bash
  python log_attack_detector.py --logfile test.log --filter-ip 1.2.3.4
  ```
- **Only failed POST login attempts to `/admin`, show 5 results max:**
  ```bash
  python log_attack_detector.py --logfile test.log --filter-url /admin --method POST --limit 5
  ```
- **Only show SQL Injection findings:**
  ```bash
  python log_attack_detector.py --logfile test.log --attack-type "SQL Injection"
  ```
- **Export report to a text file:**
  ```bash
  python log_attack_detector.py --logfile test.log --report results.txt
  ```

---

## Main CLI Arguments

| Argument           | Description                                      |
|--------------------|--------------------------------------------------|
| `--logfile`        | Path to input log file (required)                |
| `--report`         | Path to save output report file (optional)       |
| `--filter-ip`      | Only analyze requests from this IP               |
| `--filter-url`     | Only include requests containing this URL/path   |
| `--method`         | Only include requests with this HTTP method      |
| `--attack-type`    | Only show one type of attack (e.g. "SQL Injection") |
| `--limit`          | Limit the number of results per attack type      |
| `--threshold`      | Brute-force attempts needed for detection        |
| `--window`         | Time window for Brute-force (seconds)            |
| `--scan-threshold` | Requests per time window for scan detection      |
| `--scan-window`    | Time window for scan detection (seconds)         |

---

## Example Log File Format

Standard Apache Combined Log Format, e.g.:
```
192.168.0.5 - - [16/Jul/2025:12:00:00 +0000] "POST /login HTTP/1.1" 401 222 "-" "Mozilla/5.0"
10.0.0.1 - - [16/Jul/2025:12:10:10 +0000] "GET /product?id=1%20OR%201=1 HTTP/1.1" 200 333 "-" "Mozilla/5.0"
8.8.8.8 - - [16/Jul/2025:15:01:01 +0000] "GET /secret HTTP/1.1" 200 333 "-" "sqlmap"
```

---

## Project Motivation

- Demonstrates **cyber security research, detection engineering, and Python scripting skills**
- Designed for students, portfolios, and practical security interviews

---

## License

MIT License

---

*Created by [Your Name], 2025.*
