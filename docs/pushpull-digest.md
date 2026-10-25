# Digest push-pull (design note)

**Status: design only, not implemented.** The next step after scaling the push-pull interval with the cluster ([results](results/pushpull.md)), as accepted on 2026-10-24 ([Stage 2c decisions](ki01-stage2.md#decisions-stage-2c)).

## Why

A push-pull sends the whole member table both ways, about 90 bytes a record in the cost harness's clusters (17-byte names, 48 bytes of metadata, IPv4, an epoch), although in a settled cluster the two sides agree on nearly every record. Scaling the interval sends the table less often; a digest sends far less of it. Each side lists what it holds as `(name, epoch, incarnation, state)` and sends whole records only where the sides differ.

## Exchange

On one TCP connection, as today, in three frames instead of two:

1. **A → B: PushPullDigest.** A's digest of every member it holds, itself and tombstones included: `join u8, count varint`, then `count` entries, each a varint length and a body of `state u8, inc u32, node NodeId, epoch u64`. The length prefix lets later versions append fields, as push-pull records do.
2. **B → A: PushPull with wants.** B merges nothing yet. For each name, B compares its record with A's entry by the precedence rules (epoch, then incarnation, then state): where B's is later, or A lists no such name, B sends its whole record, as in a PushPull today; where A's is later, or B holds no such name, B lists the name in `wants`. Equal entries send nothing. The frame is a PushPull (0x08) followed by a PushPullWants message: `count varint, count NodeIds`.
3. **A → B: PushPull.** A merges B's records, then answers with its whole records for the names B wanted, and closes. B merges them.

Each side ends with the later of the two records for every name, which is what the full exchange gives, since equal `(epoch, incarnation, state)` means equal records: metadata, address and versions change only with a new incarnation or a new life. One round trip more; nothing else waits on a push-pull, so latency does not matter here.

Joins (`join = 1`) stay full exchanges: a joiner holds only itself, and the reply is the table it needs. Reconnects to dead members and rejoins with seeds use the digest when the peer speaks it, since they are anti-entropy too.

## Wire change

- Two new message types in version 1, from the reserved range: **0x0D PushPullDigest** and **0x0E PushPullWants**, TCP only. 0x0B and 0x0C are left alone, since version 2 uses them for its own messages.
- **A capability flag.** A node must not send a digest to a node that cannot read it: a 0.4 node that receives a frame without a PushPull closes the connection without an answer, as it does for user messages (design.md, User messages), and the initiator would read that as an empty reply. So nodes that speak the digest say so in their Alive, as a field appended after the epoch: `features varint`, bit 0 for digest push-pull. Older nodes skip it as an appended field. A node writes it only with an epoch present, which every driver since 0.3 sets; a node without an epoch never uses the digest.
- A node sends PushPullDigest only to a member whose Alive it holds with bit 0 set; with anyone else, and while it holds the member without the flag, it sends the PushPull it sends today. A node that receives a digest from a member it holds without the flag answers it all the same.
- Limits as today: the digest frame is bounded by max_stream_frame and admits at most max_new_members_per_packet new names, here as names wanted rather than records merged. A stale frame outside the replay window is answered with this node's own record only, as a stale PushPull is.

## Coexistence

- **0.4 and older nodes** never see a digest: they advertise no flag, so every exchange with them is today's full PushPull, both ways. A mixed cluster saves the bytes of exchanges between upgraded nodes only.
- **Mode `off`** nodes that speak it use it with each other, which is where it saves most: every byte of push-pull in `off` is version 1 records.
- **Mode `sign`** keeps its version 2 exchange of signed records unchanged at first. A version 2 digest would add the certificate id to each entry and send the signed record, with its proof, only where the sides differ; that is a later change, after Stage 2 resumes, and needs its own sweep. The version 1 exchange a signing node runs with unsigned members, the second exchange of a mixed view, can use the digest from the start.
- The pinned SWIM trace changes once nodes advertise the flag, since every Alive grows by one byte; mode `off` without the feature, or with it disabled for comparison, would keep the 0.4 bytes.

## What it would save

From the steady window of [pushpull-costs.csv](results/pushpull-costs.csv), mode `off`, with the interval already scaled. A record is about 90 bytes there, so one exchange is two tables of 90 bytes a member; a digest entry is 32 bytes (length 1, state 1, incarnation 4, a 17-byte name and its length 18, epoch 8), and in a settled cluster the reply carries next to nothing. The figures are inferred from those sizes, not measured:

| Cluster | Push-pull now, B/s per node | With digests | Whole node now | Whole node with digests |
| --- | ---: | ---: | ---: | ---: |
| 100 | 200 | about 36 | 392 | about 230 (-41%) |
| 1,000 | 1,001 | about 180 | 1,234 | about 410 (-67%) |
| 1,000, stress | 1,001 | about 180 | 7,666 | about 6,850 (-11%) |

Under stress the rumours of starved nodes dominate, as before. With the fixed 30 s interval the digest alone would have taken a 1,000-node node from 6,232 to about 1,300 B/s; together the two changes take it to about 410, a fifteenth. In mode `sign` a version 2 record is about 162 bytes and the exchange also carries certificates, so a version 2 digest would save more per record: most of the 11.1 KB/s per node that push-pull cost at 1,000 nodes with the fixed interval ([signed.md](results/signed.md#cost)), once it exists.

## Open questions

- Whether a node should also skip the digest when the table is small, where three frames cost more than two; below some tens of members the full table is a few kilobytes.
- Whether the flag belongs in Alive or in a capability exchange at the start of each TCP connection; the Alive field is cheaper and needs no extra round trip, but makes every Alive a byte longer.
- How a version 2 digest commits to certificates, so that a member's new certificate is not hidden behind an equal incarnation.
