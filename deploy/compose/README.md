# Live membership with Docker Compose

Requires Docker with the Compose plugin (Docker Desktop on Windows/macOS).
The image installs the published `kinship` package from PyPI, plus Starlette
and uvicorn. There is no frontend build step.

From this directory:

```sh
docker compose up --build -d
```

Open <http://localhost:8080>. Allow a few seconds for all six cards to become
ALIVE: `node-1` through `node-5`, plus `dashboard`, which is itself a kinship
node. Every service uses `seeds=["node-1:7946"]`; Docker DNS resolves the seed
hostname. Members advertise their container IP and gossip `role` and `zone`
metadata. UDP and TCP membership traffic stays on the Compose network; only
the dashboard HTTP port is published, on loopback.

The page streams the dashboard's membership view over Server-Sent Events.
Green means ALIVE, amber SUSPECT, red DEAD and grey LEFT. Dead and left cards
stay visible until that member returns. The log retains the latest 200 events
and reconnecting browsers receive a fresh snapshot and history. Event times
are recorded in UTC and displayed in your browser's local timezone. Reloading
the page retains history; restarting the dashboard clears it. Views are
eventually consistent, so timing varies with probe order and machine load.

## Try this

Run these commands in a second terminal, from this directory:

- **Freeze a process:** `docker compose pause node-3`. Watch its card turn
  SUSPECT and then DEAD. Leave it paused until DEAD appears (usually within
  tens of seconds with the LAN preset). Unlike stopping, pause gives the node
  no chance to send a graceful leave.
- **Recover it:** `docker compose unpause node-3`. Watch it return to ALIVE.
  You may see `MemberRecovered` or `MemberJoined`, depending on whether the
  suspicion had expired. Gossip and periodic rejoin can take a little time.
- **Leave cleanly:** `docker compose stop node-3` (unpause it first). The
  process handles SIGTERM and leaves the cluster; its card turns LEFT.
- **Join again:** `docker compose start node-3`. Watch `MemberJoined` and an
  ALIVE card with the same name and metadata.

Inspect processes and logs with `docker compose ps` and
`docker compose logs -f`. To remove the demo:

```sh
docker compose unpause node-3  # if it is still paused
docker compose down
```

This demo uses `insecure_plaintext=True` on its isolated Compose network.
It is an observation demo, without authentication or persistent history;
keep the HTTP port local. It uses the public `kinship.Cluster` API directly.

## Dashboard checks

Run the standard-library regression tests against the image's dependencies
(from this directory, after building the image):

```sh
docker compose run --rm --no-deps --volume "${PWD}:/tests:ro" dashboard python -m unittest discover -s /tests -v
```

The tests cover retained tombstones and rejoin, bounded history and slow
clients, resync after lost events, and SSE snapshots and disconnect cleanup.
