"""Runs examples/quickstart.py as two nodes and checks that the first sees the second join.

The release workflow runs it on each OS against kinship installed from PyPI, after the upload:

    python tools/smoke_quickstart.py 0.2.0

The argument, if given, is the version kinship must report.
"""

from __future__ import annotations

import queue
import subprocess
import sys
import threading
import time
from pathlib import Path

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "quickstart.py"
WAIT = 60.0
PORTS = (7946, 7947)


def node(lines: queue.Queue[tuple[str, str]], tag: str, *ports: int) -> subprocess.Popen[str]:
    proc = subprocess.Popen(
        [sys.executable, "-u", str(EXAMPLE), *map(str, ports)],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    def pump() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            lines.put((tag, line.rstrip()))

    threading.Thread(target=pump, daemon=True).start()
    return proc


def wait_for(lines: queue.Queue[tuple[str, str]], tag: str, text: str, deadline: float) -> bool:
    while (left := deadline - time.monotonic()) > 0:
        try:
            who, line = lines.get(timeout=left)
        except queue.Empty:
            break
        print(f"{who}: {line}", flush=True)
        if who == tag and text in line:
            return True
    print(f"timed out waiting for {tag} to print {text!r}", flush=True)
    return False


def main() -> int:
    import kinship

    print(f"kinship {kinship.__version__} from {Path(kinship.__file__).parent}", flush=True)
    if len(sys.argv) > 1 and kinship.__version__ != sys.argv[1]:
        print(f"expected kinship {sys.argv[1]}", flush=True)
        return 1
    lines: queue.Queue[tuple[str, str]] = queue.Queue()
    deadline = time.monotonic() + WAIT
    a = node(lines, "a", PORTS[0])
    procs = [a]
    try:
        if not wait_for(lines, "a", "is up on", deadline):
            return 1
        procs.append(node(lines, "b", *PORTS[::-1]))
        if not wait_for(lines, "a", "MemberJoined", deadline):
            return 1
        return 0
    finally:
        for p in procs:
            p.kill()
            p.wait()


if __name__ == "__main__":
    sys.exit(main())
