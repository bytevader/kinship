"""Names, sample keys and worker-time cluster configuration for the Compose demo."""

from __future__ import annotations

import os
import socket
import time
from pathlib import Path

import kinship

NAMES = tuple(f"node-{i}" for i in range(1, 6))
URLS = {name: f"http://{name}:8000" for name in NAMES}
KEYS = tuple(f"key-{i:02d}" for i in range(64))
#: Left by the bounce fault, so that the run Docker starts next skips the startup delay.
BOUNCE_MARKER = Path("/tmp/kinship-demo-bounce")


def membership_address() -> str:
    """Select the interface that reaches cache peers, even with multiple Docker networks."""
    for peer in NAMES:
        try:
            address = socket.gethostbyname(peer)
            # UDP connect chooses a route without sending data or requiring a live listener.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.connect((address, 7946))
                return udp.getsockname()[0]
        except OSError:
            continue
    # Hostname lookup might select the dashboard's control network. Fail startup instead.
    raise RuntimeError("cannot select membership network: no cache peer resolves or is routable")


def config() -> kinship.Config:
    """Called inside each uvicorn worker, including when Docker restarts a crashed node."""
    # A restarted node waits so peers can mark its old run DEAD before it rejoins, unless it
    # bounced: then it comes back at once and its new epoch replaces the old run directly.
    delay = float(os.environ.get("STARTUP_DELAY_SECONDS", "0"))
    if BOUNCE_MARKER.exists():
        BOUNCE_MARKER.unlink(missing_ok=True)
        delay = 0
    time.sleep(delay)
    name = os.environ.get("NODE_NAME", os.environ.get("NAME", socket.gethostname()))
    address = membership_address()
    meta = {"role": os.environ.get("ROLE", "cache"), "zone": os.environ.get("ZONE", "zone-a")}
    if name in URLS:
        meta["url"] = URLS[name]
    return kinship.Config.lan(
        name=name,
        bind=f"{address}:7946",
        seeds=[f"{seed}:7946" for seed in NAMES[:3]],
        meta=meta,
        # The dashboard starts while the cache nodes still sleep, so its first join finds no
        # seed. Retry every 5 s instead of the preset's 60 s; this also heals a partition sooner.
        rejoin_interval=5.0,
        # Plaintext is only for this demo's isolated Docker network.
        insecure_plaintext=True,
    )
