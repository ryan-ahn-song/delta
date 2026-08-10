from __future__ import annotations

import json
import mimetypes
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .models import ObservedEvent
from .runner import DockerSandboxRunner, ReplayRunner
from .service import AnalysisService, load_inline_events
from .storage import ReportStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = Path(__file__).resolve().parent / "web"
FIXTURES = PROJECT_ROOT / "fixtures"
SCENARIOS = {
    "benign": ("benign-native", "benign-native.json"),
    "suspicious": ("suspicious-canary", "suspicious-canary.json"),
    "prompt_injection": ("prompt-injection", "prompt-injection.json"),
}


class StackDeltaHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: AnalysisService):
        super().__init__(address, StackDeltaHandler)
        self.service = service


class StackDeltaHandler(BaseHTTPRequestHandler):
    server: StackDeltaHTTPServer
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            ready, reason = DockerSandboxRunner().available()
            self._json({"status": "ok", "version": "0.1.0", "docker_sandbox": {"ready": ready, "reason": reason}})
            return
        if path == "/api/analyses":
            reports = self.server.service.store.list()
            self._json({"reports": reports, "count": len(reports)})
            return
        if path.startswith("/api/analyses/"):
            analysis_id = path.rsplit("/", 1)[-1]
            report = self.server.service.store.get(analysis_id)
            if report is None:
                self._error(HTTPStatus.NOT_FOUND, "analysis not found")
            else:
                self._json(report)
            return
        if path.startswith("/api/"):
            self._error(HTTPStatus.NOT_FOUND, "route not found")
            return
        self._static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self._body()
            if path == "/api/analyze/demo":
                scenario = str(body.get("scenario", "suspicious"))
                provider = str(body.get("provider", "heuristic"))
                report = analyze_demo(self.server.service, scenario, provider)
                self._json(report.to_dict(), status=HTTPStatus.CREATED)
                return
            if path == "/api/analyze/custom":
                readme = str(body.get("readme", ""))[:200_000]
                package_json = body.get("package_json", {})
                if not isinstance(package_json, dict):
                    raise ValueError("package_json must be an object")
                events = load_inline_events(body.get("events", []))
                provider = str(body.get("provider", "heuristic"))
                window = int(body.get("window", 30))
                report = self.server.service.analyze_values(
                    readme, package_json, events, provider=provider, runner="inline-api", window=window
                )
                self._json(report.to_dict(), status=HTTPStatus.CREATED)
                return
            self._error(HTTPStatus.NOT_FOUND, "route not found")
        except (ValueError, KeyError, json.JSONDecodeError) as exc:
            self._error(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:  # Boundary: return a stable API error without a traceback.
            self._error(HTTPStatus.INTERNAL_SERVER_ERROR, f"analysis failed: {exc}")

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length > 1_500_000:
            raise ValueError("request body is too large")
        if not length:
            return {}
        value = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _json(self, value: Any, status: int = HTTPStatus.OK) -> None:
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _error(self, status: int, message: str) -> None:
        self._json({"error": message, "status": int(status)}, status=status)

    def _static(self, request_path: str) -> None:
        relative = "index.html" if request_path in ("", "/") else request_path.lstrip("/")
        candidate = (WEB_ROOT / relative).resolve()
        if WEB_ROOT.resolve() not in candidate.parents and candidate != WEB_ROOT.resolve():
            self._error(HTTPStatus.FORBIDDEN, "invalid path")
            return
        if not candidate.is_file():
            candidate = WEB_ROOT / "index.html"
        data = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8" if content_type.startswith(("text/", "application/javascript")) else content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        if os.getenv("STACK_DELTA_QUIET") != "1":
            super().log_message(format, *args)


def analyze_demo(service: AnalysisService, scenario: str, provider: str = "heuristic"):
    if scenario not in SCENARIOS:
        raise ValueError(f"unknown scenario: {scenario}")
    package_name, trace_name = SCENARIOS[scenario]
    return service.analyze(
        FIXTURES / "packages" / package_name,
        ReplayRunner(FIXTURES / "traces" / trace_name),
        provider=provider,
        window=30,
    )


def create_server(host: str = "127.0.0.1", port: int = 8765, db_path: Path | None = None, seed: bool = True) -> StackDeltaHTTPServer:
    db = db_path or Path(os.getenv("STACK_DELTA_DB", PROJECT_ROOT / "data" / "stack-delta.db"))
    service = AnalysisService(ReportStore(db))
    if seed and service.store.count() == 0:
        for scenario in SCENARIOS:
            analyze_demo(service, scenario)
    return StackDeltaHTTPServer((host, port), service)


def serve(host: str = "127.0.0.1", port: int = 8765, db_path: Path | None = None, seed: bool = True) -> None:
    server = create_server(host, port, db_path, seed)
    print(f"STACK-Delta dashboard: http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

