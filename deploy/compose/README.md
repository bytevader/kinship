# Keys in motion: a kinship Compose demo

Five FastAPI cache nodes own 64 sample keys through `kinship.ring`. A sixth
node is a dashboard at <http://localhost:8080>, with membership cards, each
node's member count, a key grid, a load generator and fault controls. Everything
updates through Server-Sent Events and plain JavaScript; there is no frontend
build step. Requires Docker with Compose, including Docker Desktop on Windows.

## Run

From this directory:

```sh
docker compose up --build -d
```

Open <http://localhost:8080>. The cache nodes wait 15 seconds on every startup
so crashes remain visible as DEAD before their automatic restart rejoins.
The dashboard starts at once and retries its seeds every 5 seconds
(`rejoin_interval=5`), so six ALIVE cards and five owner colours appear a few
seconds after the nodes finish waiting.
Each worker builds its config inside `cluster_lifespan(config)`, with seeds
`node-1:7946`, `node-2:7946` and `node-3:7946`; losing one seed is harmless.
Metadata carries `role=cache`, a zone and `url=http://node-N:8000`.

The default image builds a release wheel **from this checkout**, with maturin
and Rust 1.85.1 in a separate build stage. Cargo registry, git and target caches
persist across builds. The context is the repo root; the Dockerfile-specific
`Dockerfile.dockerignore` excludes `.git`, `.venv` and `target` directories,
including nested ones, without changing the repo's root ignore files. The
runtime is `python:3.13-slim`, installing the wheel's FastAPI extra, uvicorn
and httpx. After these APIs are published in 0.2, use the optional PyPI path:

```sh
KINSHIP_INSTALL=pypi docker compose up --build -d
```

In PowerShell, set `$env:KINSHIP_INSTALL = 'pypi'` first; remove it with
`Remove-Item Env:KINSHIP_INSTALL` to return to the source build. That path
requires `kinship[fastapi]>=0.2` on PyPI and intentionally cannot use 0.1.1.

## What the dashboard shows

Press **Start load**. It warms the 64 keys once, then GETs random keys and
occasionally PUTs new values through random cache nodes. The receiving node
uses `get_ring(where={"role": "cache"})` and forwards to the owner. An owner's
metadata URL must match that node's expected URL; keys are quoted and a hop
limit bounds forwarding while views disagree. Writes use `new_work=True`.

- Key colours identify owners. Changed owners flash; only keys that actually
  moved flash. Hover a key to see its normal owner and its new-write owner.
- SUSPECT owners retain their keys and get an amber outline, while new writes
  go to an ALIVE fallback. Reads still target the suspect owner.
- DEAD, LEFT and draining nodes own no keys. `ring.changes()` and `ring.moved()`
  drop values a node no longer owns. Draining also clears its own cache at once,
  since a node gets no membership event about its own metadata change.
- A node that was paused or cut off keeps its values, but meanwhile its peers
  suspected it or declared it dead and sent writes elsewhere. When it comes back
  it refutes by raising its incarnation, and on seeing that it drops its whole
  cache, so its returning keys read as misses rather than stale values.
- Successes count successful GETs and PUTs. Misses are 404s from cold keys,
  including keys lost with an owner; errors are timeouts or failed requests.
  Initial warming can also fail if you inject a fault before it finishes.
- **Sees N members** is polled from that node's `/cluster/members`. During a
  failure, counts can disagree. If its HTTP API cannot be reached, the card
  explicitly shows its last count as stale. DEAD and LEFT cards remain visible.
- Amber log lines are fault/load actions; blue lines are ring changes; other
  lines are membership events. History is bounded to 200 timestamped entries.
  Browsers reconnect to a current snapshot. Restarting the dashboard clears
  counters/history; refreshing the page does not.

This is a **volatile cache**, without replication or key transfer. A new owner
starts cold, and restarting/undraining a node does not restore its old values.
Membership and ownership are eventually consistent, rather than a distributed
lock or a guarantee against concurrent writes during a partition.

## Try this

Start load and let warming finish first. Use the buttons on `node-3`'s card;
disable random chaos before manual faults. Recover one fault before starting
another. Docker buttons require the optional profile below.

| Fault / button | What to watch | Recovery |
| --- | --- | --- |
| **Stall 20s** | The FastAPI event loop blocks with `time.sleep(20)`. HTTP calls time out and its member count becomes stale, but the card stays ALIVE and keys keep their owner: kinship runs on its own Rust thread. | Automatic after 20 seconds. |
| **Crash** | `os._exit(1)` sends no leave. Watch SUSPECT, DEAD, moved keys and misses, then MemberJoined when `restart: on-failure` starts it again. | Automatic, including the 15-second startup delay. |
| **Leave** | The node calls `leave()` and exits 0. Watch LEFT, moved keys and misses; Docker leaves it down. | **Start** with the chaos profile, or `docker compose start node-3`; the dashboard frees the fault slot once the node reports itself ALIVE. |
| **Drain** | Metadata changes to `role=draining`. The member stays ALIVE but its keys move to cache members. | **Undrain** returns `role=cache`; some keys move back, cold. |
| **Pause** | Docker freezes the entire process, including kinship's thread. Watch SUSPECT outlines, then DEAD and changed owners. | **Unpause**; wait for recovery/rejoin. |
| **Kill** | SIGKILL models a process crash. Watch failure detection and lost values. Docker counts a kill as a manual stop, so `restart: on-failure` leaves it down. | **Start**. |
| **Restart** | Docker stops and starts the process. A normal stop sends LEFT; values are lost and the node rejoins after the startup delay. | Automatic. |
| **Partition** | Disconnects only that cache node from the membership network. HTTP becomes unreachable; peers suspect and mark it DEAD, while it marks all of them DEAD. Keys move and errors/misses rise. | **Reconnect** restores its Docker DNS alias; it rejoins within seconds. Its own stale rumours can briefly flip a healthy member to SUSPECT or DEAD until that member refutes, so watch for a second, short RingChanged. |

A crash on `node-3`, six seconds in: it is DEAD, its card shows its HTTP API
is gone, and its 12 keys now belong to the other four nodes.

![node-3 DEAD after a crash, with its keys moved to the other nodes](screenshots/crash.jpg)

A partition of `node-3`: the same picture from the dashboard, while views
still disagree, so the dashboard sees 5 members and `node-1` still sees 6.

![node-3 DEAD behind a partition, with member counts that disagree](screenshots/partition.jpg)

**Start chaos** applies a random fault every configured interval (20 seconds
by default), holding at most one fault slot at a time. It waits for timer
recovery before taking another slot: unpause, start, reconnect or undrain;
stalls recover on their own. Recovery failures are logged and retried. Manual
faults block random faults until recovered; a starting worker retains its
fault slot until its HTTP API is ready. **Stop chaos** also initiates
recovery; if a stall is still running, wait for it to finish. Without the
Docker helper, random chaos uses only stalls and drains, which can recover
without access to Docker.

## Opt-in Docker faults

```sh
docker compose --profile chaos up --build -d
```

The dashboard discovers the helper and reveals Pause/Unpause, Kill,
Restart/Start and Partition/Reconnect. The helper is on a separate internal
control network shared only with the dashboard; it has no published port.
Cache APIs, including in-process fault routes and `/cluster`, are only on
the Compose network. Only dashboard HTTP is published, on `127.0.0.1:8080`.

**The Docker socket gives root-level control over the host.** This is why it
is opt-in, for a disposable local demo, with a loopback-only dashboard.
The helper's allowlist reduces accidental reach: it accepts only the listed
actions and `node-1` through `node-5`, checks Compose container/network labels,
and uses the Docker HTTP API without passing input to a shell. It is not a
security boundary against a compromised helper or dashboard. Do not publish
the dashboard remotely or attach the helper to a production Docker daemon.
Because a loopback port is still reachable from any page open in your browser,
the dashboard only answers the `Host` names `localhost` and `127.0.0.1`
(against DNS rebinding) and refuses a control request whose `Origin` is
another site.

Membership uses `insecure_plaintext=True`, with a comment in `common.py`,
only for the isolated demo membership network. No `.env` key is required.

To turn the profile off, stop random chaos, recover any manual faults, then:

```sh
docker compose --profile chaos stop chaos
docker compose --profile chaos rm -f chaos
```

Docker buttons disappear after the next helper health check. Removing the
helper does not itself recover a paused or partitioned container.

## Tests and cleanup

The image includes standard-library unit tests for the fault allowlist,
Docker container/network scope, scheduler with a fake clock, safe forwarding,
ownership and eviction with a fake ring, and the SSE view:

```sh
docker compose run --rm --no-deps dashboard python -m unittest discover -s /app -v
```

Inspect services with `docker compose ps` and logs with `docker compose logs -f`.
To stop the demo, first Stop chaos and recover manual faults (Unpause,
Reconnect, Start or Undrain). Then:

```sh
docker compose --profile chaos down
```

If a manual fault left the page unusable, `docker compose unpause node-3`
recovers a pause; for a partition, restore the membership network with
`docker network connect --alias node-3 kinship-demo_membership kinship-demo-node-3-1`.
Then bring the project down. No data volumes persist cache values.
