import re
import argparse
from collections import defaultdict, deque
from datetime import datetime, timedelta

# Regex for parsing Apache log format (Common/Combined Log Format)
APACHE_LOG_PATTERN = (
    r'(?P<ip>\S+) \S+ \S+ \[(?P<datetime>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d{3}) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)"'
)

DATETIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"

# Patterns to detect SQL Injection in URL/query
SQLI_PATTERNS = [
    r"(\%27)|(')",               # '
    r"(\%3D)|(=)",               # =
    r"(\%2D\%2D)|(--)",          # --
    r"(\%23)|(#)",               # #
    r"(?i)\b(select|union|insert|update|drop|delete)\b",
    r"(?i)\bOR\b\s+1=1",
    r"(?i)\bUNION\b.*\bSELECT\b",
    r"(?i)\/etc\/passwd",
]

# List of sensitive paths whose access might indicate attack
SENSITIVE_PATHS = [
    "/admin", "/login", "/wp-admin", "/phpmyadmin", "/dashboard",
    ".env", "/.git", "/config", "/etc/passwd"
]

# Suspicious user agents typical to known scanning/attack tools
SUSPICIOUS_USER_AGENTS = [
    "nikto", "sqlmap", "curl", "python-requests", "fuzz", "nmap"
]

def parse_log_line(line):
    """
    Parse a single Apache log line.
    Returns a dict with fields (ip, datetime, method, url, status, size, agent) or None if not matched.
    """
    match = re.match(APACHE_LOG_PATTERN, line)
    if not match:
        return None
    d = match.groupdict()
    try:
        d["datetime"] = datetime.strptime(d["datetime"], DATETIME_FORMAT)
    except Exception:
        return None
    d["status"] = int(d["status"])
    d["size"] = int(d["size"])
    d["url"] = d["url"].lower()
    d["agent"] = d["agent"].lower()
    d["method"] = d["method"].upper()
    return d

def detect_bruteforce(logs, threshold=4, window_sec=30):
    """
    Detects brute-force attacks by counting POST login failures (401/403) from same IP in a short time window.
    Returns: list of findings with IP, start/end, count.
    """
    findings = []
    ip_map = defaultdict(list)

    # Group log entries by IP and collect timestamps of failed login attempts
    for entry in logs:
        if entry["method"] == "POST" and entry["status"] in [401, 403]:
            ip_map[entry["ip"]].append(entry["datetime"])

    # Use a deque to maintain a sliding window of timestamps for each IP
    for ip, times in ip_map.items():
        dq = deque()
        for t in times:
            dq.append(t)
            while (t - dq[0]).total_seconds() > window_sec: 
                dq.popleft()
            if len(dq) >= threshold:
                findings.append({
                    "type": "Brute-force",
                    "ip": ip,
                    "start": dq[0],
                    "end": dq[-1],
                    "count": len(dq),
                })
                break
    return findings

def detect_sql_injection(logs):
    """
    Detect SQL Injection attempts by regex patterns in the requested URL.
    """
    findings = []
    for entry in logs:
        for pat in SQLI_PATTERNS:
            if re.search(pat, entry["url"]):
                findings.append({
                    "type": "SQL Injection",
                    "ip": entry["ip"],
                    "url": entry["url"],
                    "datetime": entry["datetime"],
                    "method": entry["method"]
                })
                break
    return findings

def detect_sensitive_paths(logs):
    """
    Detect access attempts to sensitive endpoints (e.g., /admin, /login, /.env, etc.)
    """
    findings = []
    for entry in logs:
        for path in SENSITIVE_PATHS:
            if path in entry["url"]:
                findings.append({
                    "type": "Sensitive Path",
                    "ip": entry["ip"],
                    "url": entry["url"],
                    "datetime": entry["datetime"],
                    "method": entry["method"]
                })
                break
    return findings

def detect_scan(logs, threshold=10, window_sec=60):
    """
    Detect scanning or flood attempts - many requests from the same IP in a short window.
    """
    findings = []
    ip_map = defaultdict(list)
    for entry in logs:
        ip_map[entry["ip"]].append(entry["datetime"])
    for ip, times in ip_map.items():
        times.sort()
        dq = deque()
        for t in times:
            dq.append(t)
            while (t - dq[0]).total_seconds() > window_sec:
                dq.popleft()
            if len(dq) >= threshold:
                findings.append({
                    "type": "Scanning/Rate-limit",
                    "ip": ip,
                    "start": dq[0],
                    "end": dq[-1],
                    "count": len(dq),
                })
                break
    return findings

def detect_user_agents(logs):
    """
    Detect suspicious user agents (sqlmap, curl, nikto, etc).
    """
    findings = []
    for entry in logs:
        for bad_ua in SUSPICIOUS_USER_AGENTS:
            if bad_ua in entry["agent"]:
                findings.append({
                    "type": "Suspicious User-Agent",
                    "ip": entry["ip"],
                    "user_agent": entry["agent"],
                    "url": entry["url"],
                    "datetime": entry["datetime"],
                    "method": entry["method"]
                })
                break
    return findings

def filter_entries(entries, filter_url=None, method=None):
    """
    Filters log entries by URL substring and/or HTTP method.
    """
    filtered = []
    for entry in entries:
        if filter_url and filter_url.lower() not in entry["url"]:
            continue
        if method and entry.get("method") and entry["method"].upper() != method.upper():
            continue
        filtered.append(entry)
    return filtered

def generate_report(all_findings, output_file=None, attack_type=None, limit=None):
    """
    Print (and optionally save) a formatted report with all attack findings.
    Optionally filter by attack type and/or limit number of results.
    """
    report_lines = []
    report_lines.append("=== Suspicious Activity Report ===")
    all_events = 0
    unique_ips = set()
    for cat, findings in all_findings.items():
        if attack_type and cat != attack_type:
            continue
        if not findings:
            continue
        report_lines.append(f"\n--- {cat} ---")
        count = 0
        for f in findings:
            all_events += 1
            unique_ips.add(f["ip"])
            if f["type"] == "Brute-force":
                report_lines.append(f"🛑 Brute-force: IP {f['ip']} ({f['count']} attempts, {f['start']} - {f['end']})")
            elif f["type"] == "SQL Injection":
                report_lines.append(f"🛑 SQLi: IP {f['ip']} url: {f['url']} method: {f.get('method', '')} ({f['datetime']})")
            elif f["type"] == "Sensitive Path":
                report_lines.append(f"🛑 Sensitive: IP {f['ip']} url: {f['url']} method: {f.get('method', '')} ({f['datetime']})")
            elif f["type"] == "Scanning/Rate-limit":
                report_lines.append(f"🛑 Scan: IP {f['ip']} ({f['count']} requests in {f['start']} - {f['end']})")
            elif f["type"] == "Suspicious User-Agent":
                report_lines.append(f"🛑 UserAgent: IP {f['ip']} agent: {f['user_agent']} url: {f['url']} method: {f.get('method', '')}")
            count += 1
            if limit and count >= limit:
                break
    report_lines.append(f"\n== Summary ==\nTotal events: {all_events}\nUnique IPs: {len(unique_ips)}")
    report_lines.append("-----------------------------")
    report_lines.append("Report generated by LogAttackDetector 🐍")
    output = "\n".join(report_lines)
    print(output)
    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(output)

def main():
    """
    Main CLI entrypoint.
    Handles arguments, parses log file, runs all detections, applies filters, and outputs report.
    """
    parser = argparse.ArgumentParser(description="Log Attack Detector")
    parser.add_argument("--logfile", type=str, required=True, help="Log file path")
    parser.add_argument("--report", type=str, default=None, help="Output report file")
    parser.add_argument("--threshold", type=int, default=4, help="Brute-force threshold")
    parser.add_argument("--scan-threshold", type=int, default=10, help="Scan (flood) threshold")
    parser.add_argument("--window", type=int, default=30, help="Brute-force window in seconds")
    parser.add_argument("--scan-window", type=int, default=60, help="Scan window in seconds")
    parser.add_argument("--filter-ip", type=str, default=None, help="Only analyze events from this IP")
    parser.add_argument("--filter-url", type=str, default=None, help="Only show events matching this URL/path")
    parser.add_argument("--attack-type", type=str, default=None, choices=["Brute-force", "SQL Injection", "Sensitive Path", "Scanning/Rate-limit", "Suspicious User-Agent"], help="Only show a specific attack type")
    parser.add_argument("--limit", type=int, default=None, help="Limit the number of results")
    parser.add_argument("--method", type=str, default=None, help="Only show events with this HTTP method (e.g., GET, POST)")
    args = parser.parse_args()

    # Parse log file into structured entries
    parsed_logs = []
    with open(args.logfile, "r", encoding="utf-8") as f:
        for line in f:
            entry = parse_log_line(line)
            if entry:
                if args.filter_ip:
                    if entry["ip"] == args.filter_ip:
                        parsed_logs.append(entry)
                else:
                    parsed_logs.append(entry)

    # Apply filtering by URL and/or METHOD before detections
    filtered_logs = filter_entries(parsed_logs, filter_url=args.filter_url, method=args.method)

    # Run attack detections
    findings = {
        "Brute-force": detect_bruteforce(filtered_logs, threshold=args.threshold, window_sec=args.window),
        "SQL Injection": detect_sql_injection(filtered_logs),
        "Sensitive Paths": detect_sensitive_paths(filtered_logs),
        "Scanning": detect_scan(filtered_logs, threshold=args.scan_threshold, window_sec=args.scan_window),
        "User-Agent": detect_user_agents(filtered_logs),
    }

    # Generate and print/save report
    generate_report(
        findings,
        output_file=args.report,
        attack_type=args.attack_type,
        limit=args.limit
    )

if __name__ == "__main__":
    main()
