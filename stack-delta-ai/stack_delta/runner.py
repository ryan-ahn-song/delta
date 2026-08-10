from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path

from .models import ObservedEvent
from .trace_parser import load_replay, parse_trace_files


class RunnerError(RuntimeError):
    pass


class BehaviorRunner(ABC):
    name = "base"

    @abstractmethod
    def run(self, package_dir: Path, window: int = 30) -> list[ObservedEvent]:
        raise NotImplementedError


class ReplayRunner(BehaviorRunner):
    name = "safe-replay"

    def __init__(self, replay_file: Path):
        self.replay_file = replay_file

    def run(self, package_dir: Path, window: int = 30) -> list[ObservedEvent]:
        del package_dir, window
        return load_replay(self.replay_file)


class DockerSandboxRunner(BehaviorRunner):
    """Runs only a local package directory inside a networkless disposable container."""

    name = "docker-strace-sandbox"

    def __init__(self, image: str = "stack-delta-sandbox:dev", keep_output: bool = False):
        self.image = image
        self.keep_output = keep_output

    def available(self) -> tuple[bool, str]:
        docker = shutil.which("docker")
        if not docker:
            return False, "docker executable was not found"
        probe = subprocess.run(
            [docker, "image", "inspect", self.image], capture_output=True, text=True, timeout=15
        )
        if probe.returncode != 0:
            return False, f"sandbox image is missing; build {self.image} first"
        return True, "ready"

    def run(self, package_dir: Path, window: int = 30) -> list[ObservedEvent]:
        package_dir = package_dir.resolve()
        if not package_dir.is_dir() or not (package_dir / "package.json").is_file():
            raise RunnerError("Only an existing local npm package directory is accepted")
        if not 1 <= window <= 300:
            raise RunnerError("Observation window must be between 1 and 300 seconds")
        ready, reason = self.available()
        if not ready:
            raise RunnerError(reason)

        output = Path(tempfile.mkdtemp(prefix="stack-delta-run-"))
        os.chmod(output, 0o777)
        command = [
            "docker", "run", "--rm",
            "--network", "none",
            "--read-only",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--pids-limit", "128",
            "--memory", "384m",
            "--cpus", "1.0",
            "--user", "10001:10001",
            "--tmpfs", "/work:rw,size=192m,mode=1777",
            "--tmpfs", "/home/sandbox:rw,size=32m,mode=0700,uid=10001,gid=10001",
            "--mount", f"type=bind,src={package_dir},dst=/input,readonly",
            "--mount", f"type=bind,src={output},dst=/output",
            "-e", "HOME=/home/sandbox",
            "-e", "CANARY_API_TOKEN=STACK_DELTA_FAKE_TOKEN",
            "-e", "STACK_DELTA_ENV_LOG=/output/env.jsonl",
            self.image,
            str(window),
        ]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, timeout=window + 20)
            (output / "runner.json").write_text(json.dumps({
                "returncode": completed.returncode,
                "stdout": completed.stdout[-4000:],
                "stderr": completed.stderr[-4000:],
            }, ensure_ascii=False, indent=2), encoding="utf-8")
            events = parse_trace_files(output)
            if not events and completed.returncode not in (0, 124, 137):
                raise RunnerError(f"Sandbox failed before producing trace events: {completed.stderr[-600:]}")
            return events
        except subprocess.TimeoutExpired as exc:
            raise RunnerError("Sandbox wrapper exceeded its hard timeout") from exc
        finally:
            if not self.keep_output:
                shutil.rmtree(output, ignore_errors=True)


def build_sandbox_image(project_root: Path, image: str = "stack-delta-sandbox:dev") -> None:
    if not shutil.which("docker"):
        raise RunnerError("docker executable was not found")
    command = ["docker", "build", "-t", image, str(project_root / "sandbox")]
    completed = subprocess.run(command)
    if completed.returncode:
        raise RunnerError("Sandbox image build failed")

