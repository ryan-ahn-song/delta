from __future__ import annotations

import json
import re
from pathlib import Path

from .models import ObservedEvent


TIMESTAMP_RE = re.compile(r"^(?:\[pid\s+\d+\]\s+)?(?P<ts>\d+\.\d+)\s+")
CALL_RE = re.compile(r"(?P<call>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s+=\s+(?P<result>.+)$")
QUOTED_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
IP_RE = re.compile(r'inet_addr\("([0-9.]+)"\)')
IP6_RE = re.compile(r'inet_pton\(AF_INET6,\s*"([0-9a-fA-F:]+)"')
PORT_RE = re.compile(r'(?:htons\()?([0-9]{1,5})\)?')

READ_CALLS = {"open", "openat", "openat2", "access", "stat", "lstat", "newfstatat", "readlink", "readlinkat"}
WRITE_CALLS = {"creat", "unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat", "rmdir", "chmod", "fchmodat", "truncate"}
PROCESS_CALLS = {"execve", "execveat"}


def parse_trace_files(trace_dir: Path) -> list[ObservedEvent]:
    paths = sorted(trace_dir.glob("trace*"))
    events: list[ObservedEvent] = []
    for path in paths:
        if path.is_file():
            events.extend(parse_strace(path.read_text(encoding="utf-8", errors="replace")))
    env_path = trace_dir / "env.jsonl"
    if env_path.is_file():
        events.extend(parse_env_sensor(env_path.read_text(encoding="utf-8", errors="replace")))
    return deduplicate_events(events)


def parse_strace(text: str) -> list[ObservedEvent]:
    events: list[ObservedEvent] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or "<unfinished ...>" in line or "resumed>" in line:
            continue
        timestamp = 0.0
        stamp = TIMESTAMP_RE.match(line)
        if stamp:
            timestamp = float(stamp.group("ts"))
            line = line[stamp.end():]
        call_match = CALL_RE.search(line)
        if not call_match:
            continue
        call = call_match.group("call")
        args = call_match.group("args")
        result = call_match.group("result")
        status = "attempted" if result.lstrip().startswith("-1") else "success"
        quoted = [_unescape(value) for value in QUOTED_RE.findall(args)]

        if call in PROCESS_CALLS and quoted:
            events.append(ObservedEvent("process_spawn", quoted[0], status, timestamp, "strace", line[:500]))
        elif call == "connect":
            host = _network_host(args)
            if host:
                events.append(ObservedEvent("network_connect", host, status, timestamp, "strace", line[:500]))
        elif call in READ_CALLS and quoted:
            path = _path_arg(quoted)
            if not path:
                continue
            if path.startswith("/proc/") and not path.startswith("/proc/self/"):
                capability = "process_inspect"
            elif _is_write_open(call, args):
                capability = "file_write"
            else:
                capability = "file_read"
            events.append(ObservedEvent(capability, path, status, timestamp, "strace", line[:500]))
        elif call in WRITE_CALLS and quoted:
            path = _path_arg(quoted)
            if path:
                events.append(ObservedEvent("file_write", path, status, timestamp, "strace", line[:500]))
    return events


def parse_env_sensor(text: str) -> list[ObservedEvent]:
    result: list[ObservedEvent] = []
    for line in text.splitlines():
        try:
            item = json.loads(line)
            name = str(item["name"])
            timestamp = float(item.get("timestamp", 0))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        result.append(ObservedEvent("env_read", name, "success", timestamp, "node-env-sensor", "value redacted"))
    return result


def load_replay(path: Path) -> list[ObservedEvent]:
    values = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(values, list):
        raise ValueError("Replay trace must be a JSON array")
    return deduplicate_events([ObservedEvent.from_dict(value) for value in values])


def deduplicate_events(events: list[ObservedEvent]) -> list[ObservedEvent]:
    result: list[ObservedEvent] = []
    seen: dict[tuple[str, str, str], int] = {}
    for event in sorted(events, key=lambda item: item.timestamp):
        key = (event.capability, event.target, event.status)
        if key in seen:
            continue
        seen[key] = len(result)
        result.append(event)
    return result


def _path_arg(values: list[str]) -> str:
    for value in values:
        if value.startswith(("/", "./", "../")):
            return value
    return values[0] if values else ""


def _is_write_open(call: str, args: str) -> bool:
    if call not in {"open", "openat", "openat2"}:
        return False
    return any(flag in args for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"))


def _network_host(args: str) -> str:
    ip_match = IP_RE.search(args) or IP6_RE.search(args)
    if not ip_match:
        unix = re.search(r'sun_path="([^"]+)"', args)
        return f"unix:{unix.group(1)}" if unix else ""
    port_match = re.search(r"sin6?_port=htons\((\d+)\)", args)
    port = port_match.group(1) if port_match else "0"
    return f"{ip_match.group(1)}:{port}"


def _unescape(value: str) -> str:
    return bytes(value, "utf-8").decode("unicode_escape", errors="replace")

