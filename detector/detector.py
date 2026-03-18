import json
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

NGINX_ACCESS_LOG = Path(os.getenv("NGINX_ACCESS_LOG", "/lab-logs/nginx/access.log"))
AUTH_LOG = Path(os.getenv("AUTH_LOG", "/lab-logs/auth.log"))
ALERT_OUTPUT = Path(os.getenv("ALERT_OUTPUT", "/lab-alerts/alerts.jsonl"))
SUSPICIOUS_PATH_THRESHOLD = int(os.getenv("SUSPICIOUS_PATH_THRESHOLD", "5"))
HTTP_4XX_THRESHOLD = int(os.getenv("HTTP_4XX_THRESHOLD", "10"))
SSH_FAILURE_THRESHOLD = int(os.getenv("SSH_FAILURE_THRESHOLD", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
COOLDOWN_SECONDS = int(os.getenv("COOLDOWN_SECONDS", "120"))

SUSPICIOUS_PATTERNS = [
    "/.env",
    "/wp-login.php",
    "/server-status",
    "/admin",
    "/login",
    "/phpmyadmin",
]

AUTH_REGEX = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

state = {
    "suspicious_paths": defaultdict(deque),
    "http_4xx": defaultdict(deque),
    "ssh_failures": defaultdict(deque),
    "cooldowns": {},
    "offsets": {},
}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def trim_events(bucket: deque, now_ts: float) -> None:
    while bucket and now_ts - bucket[0] > WINDOW_SECONDS:
        bucket.popleft()


def can_alert(alert_key: str, now_ts: float) -> bool:
    last = state["cooldowns"].get(alert_key, 0)
    if now_ts - last >= COOLDOWN_SECONDS:
        state["cooldowns"][alert_key] = now_ts
        return True
    return False


def emit_alert(rule_name: str, severity: str, source: str, details: dict) -> None:
    payload = {
        "timestamp": utc_now().isoformat(),
        "rule": rule_name,
        "severity": severity,
        "source": source,
        "details": details,
    }
    ALERT_OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with ALERT_OUTPUT.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
    print(json.dumps(payload, ensure_ascii=False), flush=True)


def process_nginx_line(line: str) -> None:
    try:
        data = json.loads(line)
    except json.JSONDecodeError:
        return

    now_ts = time.time()
    ip = data.get("remote_addr", "unknown")
    path = data.get("path", "")
    status = int(data.get("status", 0))

    if any(path.startswith(pattern) for pattern in SUSPICIOUS_PATTERNS):
        key = f"{ip}:{path}"
        bucket = state["suspicious_paths"][key]
        bucket.append(now_ts)
        trim_events(bucket, now_ts)
        if len(bucket) >= SUSPICIOUS_PATH_THRESHOLD and can_alert(f"suspicious:{key}", now_ts):
            emit_alert(
                rule_name="Repeated suspicious path access",
                severity="medium",
                source="nginx",
                details={
                    "ip": ip,
                    "path": path,
                    "hits_in_window": len(bucket),
                    "window_seconds": WINDOW_SECONDS,
                },
            )

    if 400 <= status < 500:
        bucket = state["http_4xx"][ip]
        bucket.append(now_ts)
        trim_events(bucket, now_ts)
        if len(bucket) >= HTTP_4XX_THRESHOLD and can_alert(f"http4xx:{ip}", now_ts):
            emit_alert(
                rule_name="High volume of HTTP 4xx responses",
                severity="low",
                source="nginx",
                details={
                    "ip": ip,
                    "events_in_window": len(bucket),
                    "window_seconds": WINDOW_SECONDS,
                },
            )


def process_auth_line(line: str) -> None:
    match = AUTH_REGEX.search(line)
    if not match:
        return

    now_ts = time.time()
    ip = match.group("ip")
    user = match.group("user")
    key = f"{ip}:{user}"

    bucket = state["ssh_failures"][key]
    bucket.append(now_ts)
    trim_events(bucket, now_ts)

    if len(bucket) >= SSH_FAILURE_THRESHOLD and can_alert(f"ssh:{key}", now_ts):
        emit_alert(
            rule_name="Possible SSH brute-force activity",
            severity="high",
            source="auth.log",
            details={
                "ip": ip,
                "user": user,
                "failures_in_window": len(bucket),
                "window_seconds": WINDOW_SECONDS,
            },
        )


def ensure_file(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)


def read_new_lines(path: Path):
    ensure_file(path)
    offset = state["offsets"].get(str(path), 0)
    size = path.stat().st_size
    if size < offset:
        offset = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        fh.seek(offset)
        for line in fh:
            yield line.rstrip("\n")
        state["offsets"][str(path)] = fh.tell()


def main() -> None:
    print(
        json.dumps(
            {
                "timestamp": utc_now().isoformat(),
                "event": "detector_started",
                "nginx_access_log": str(NGINX_ACCESS_LOG),
                "auth_log": str(AUTH_LOG),
            }
        ),
        flush=True,
    )

    while True:
        for line in read_new_lines(NGINX_ACCESS_LOG):
            process_nginx_line(line)

        for line in read_new_lines(AUTH_LOG):
            process_auth_line(line)

        time.sleep(1)


if __name__ == "__main__":
    main()
