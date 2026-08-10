from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .api import FIXTURES, SCENARIOS, analyze_demo, serve
from .policy import PolicyEngine
from .runner import DockerSandboxRunner, ReplayRunner, RunnerError, build_sandbox_image
from .service import AnalysisService
from .storage import ReportStore


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="stack-delta", description="npm declaration-behavior mismatch detector")
    root.add_argument("--db", type=Path, default=PROJECT_ROOT / "data" / "stack-delta.db")
    commands = root.add_subparsers(dest="command", required=True)

    serve_cmd = commands.add_parser("serve", help="start the local dashboard")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8765)
    serve_cmd.add_argument("--no-seed", action="store_true")

    demo_cmd = commands.add_parser("demo", help="analyze a safe replay scenario")
    demo_cmd.add_argument("--scenario", choices=SCENARIOS, default="suspicious")
    demo_cmd.add_argument("--provider", choices=("heuristic", "openai"), default="heuristic")
    demo_cmd.add_argument("--output", type=Path)

    analyze_cmd = commands.add_parser("analyze", help="analyze a local package with a replay trace")
    analyze_cmd.add_argument("package_dir", type=Path)
    analyze_cmd.add_argument("--trace", type=Path, required=True)
    analyze_cmd.add_argument("--provider", choices=("heuristic", "openai"), default="heuristic")
    analyze_cmd.add_argument("--window", type=int, default=30)
    analyze_cmd.add_argument("--output", type=Path)

    sandbox_cmd = commands.add_parser("analyze-sandbox", help="run a local package in the Docker sandbox")
    sandbox_cmd.add_argument("package_dir", type=Path)
    sandbox_cmd.add_argument("--provider", choices=("heuristic", "openai"), default="heuristic")
    sandbox_cmd.add_argument("--window", type=int, default=30)
    sandbox_cmd.add_argument("--image", default="stack-delta-sandbox:dev")
    sandbox_cmd.add_argument("--output", type=Path)

    build_cmd = commands.add_parser("build-sandbox", help="build the networkless tracing image")
    build_cmd.add_argument("--image", default="stack-delta-sandbox:dev")

    commands.add_parser("list", help="list recent analysis reports")
    return root


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "serve":
        serve(args.host, args.port, args.db, seed=not args.no_seed)
        return 0

    service = AnalysisService(ReportStore(args.db), PolicyEngine())
    try:
        if args.command == "demo":
            report = analyze_demo(service, args.scenario, args.provider)
            return _emit(report.to_dict(), args.output)
        if args.command == "analyze":
            report = service.analyze(
                args.package_dir, ReplayRunner(args.trace), provider=args.provider, window=args.window
            )
            return _emit(report.to_dict(), args.output)
        if args.command == "analyze-sandbox":
            report = service.analyze(
                args.package_dir,
                DockerSandboxRunner(args.image),
                provider=args.provider,
                window=args.window,
            )
            return _emit(report.to_dict(), args.output)
        if args.command == "build-sandbox":
            build_sandbox_image(PROJECT_ROOT, args.image)
            print(f"built sandbox image: {args.image}")
            return 0
        if args.command == "list":
            print(json.dumps(service.store.list(), ensure_ascii=False, indent=2))
            return 0
    except (ValueError, FileNotFoundError, RunnerError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 1


def _emit(value: dict, output: Path | None) -> int:
    rendered = json.dumps(value, ensure_ascii=False, indent=2)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
        print(output.resolve())
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

