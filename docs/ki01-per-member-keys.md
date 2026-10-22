# KI-01: per-member keys

A plan for closing KI-01 in SECURITY.md: any member that holds the cluster key can declare any node dead, claim any name, and send user messages in any member's name. Proposed on 2026-10-15. Stage 1 identity primitives and explicitly selected codec support now exist in kinship-proto; the runtime feature remains planned for an opt-in release after 1.0. The protocol it changes is in `docs/design.md`, and the threat model it builds on is in SECURITY.md.

## Summary

- Every member gets an Ed25519 signing key of its own, bound to its name by a certificate from a cluster CA that the operator runs. Nodes are configured with the CA's public key, not with each other's.
- Every statement a member makes is signed by it: its own Alive and Left, its accusations (Suspect, Dead), its Acks and Nacks, its user messages and broadcasts. Relayed statements travel with their author's signature, so push-pull and gossip carry them unchanged, and a node never relays what it could not verify.
- An accusation counts as one reporter. A Dead from another member no longer kills at once: it confirms a suspicion, and a node declares the member dead when its own timer runs out, or at once when its suspicion has at least K + 1 distinct signed reporters, as many as Lifeguard needs for the minimum timeout.
- The cluster key stays, for confidentiality, the replay window and to keep traffic that is not from a member from costing a signature check. Removing a member no longer needs a key rotation on every other node: a CA-signed revocation, handed to any one node, spreads by gossip.
- Wire version 2 is version 1 with signatures appended to the messages that carry them and two new message types. 0.4 nodes skip what they do not know, so a cluster moves to it one node at a time, and KI-01 is closed once every node runs with `require_signatures`.
- Cost, measured in kinship-sim with realistic names and metadata: 71% to 90% more bytes per node, from 0.85 to 1.47 KB/s at 100 nodes and from 6.7 to 12.0 KB/s at 1,000 in a calm cluster, most of it the signatures in push-pull records and, under stress, in rumours. Signing takes 29 µs and verifying 82 µs on the laptop used for the tuning sweep; a node checked 1 to 14 signatures a second, at most about a thousandth of a core.

The choices accepted by Nikola on 2026-10-16 are recorded under [Decisions](#decisions). Stage 1 codec support exists; the remaining runtime feature is future work and KI-01 stays Accepted until the completion criteria below are met.

**Implementation status.** [Stage 1 notes](ki01-stage1.md) specify the exact canonical grammar, signature domains and replay bindings used by the experimental codec, including details absent from the size sketch below. Every member-signed statement binds its certificate id, probe answers explicitly name their requester and target, and push-pull preserves the original Alive incarnation beside an independent Left proof. These additions require Stage 2 to remeasure the sketch's bandwidth and size estimates. The notes also record the probe challenge security decision raised during implementation. Stages 2a and 2b add an experimental mode `sign` to kinship-core, described in the [Stage 2 notes](ki01-stage2.md): signed membership statements, probe answers bound to a per-round challenge, and signed user messages and broadcasts. Stages 2c to 5 remain. Nodes in mode `off`, the default, still advertise and emit version 1, and no mode enforces member signatures yet. KI-01 remains Accepted.

## 1. Threat model

The attacker is a member that holds the cluster key (attacker 2 in SECURITY.md). With per-member keys it holds its own signing key and certificate as well, but no other member's. A holder of the cluster key that has no certificate of its own, such as a key copied out of a configuration file, is weaker still: it signs nothing anyone accepts, and can only replay what it recorded.

The table lists what a key holder can do today, and what is left of it once the cluster requires signatures. Stopped means one member can no longer do it at all; narrowed means it can do less of it, or only under its own name, where the cluster can see it and revoke it; stays means signatures do not touch it.

| Today a member holding the key can | With signatures required |
| --- | --- |
| Declare any node dead at once with one sealed Dead (the KI-01 reproduction) | **Stopped.** A Dead from a third party is one signed reporter. The member can start a suspicion, which the node refutes; see Accuse below. |
| Make a node look as if it left, with a Dead naming the node as its own author | **Stopped.** Left is signed by the member that leaves. |
| Forge an Alive for any member: change its metadata, keep a dead member alive, or bring back one that left | **Stopped** for live and dead members. **Narrowed** for a member whose tombstone was reaped: its last signed Alive can be replayed to bring it back as a phantom until its certificate expires (see [Replays of signed statements](#replays-of-signed-statements)). |
| Forge a restart, an Alive at a later epoch, so applications see MemberLeft and MemberJoined and fencing tokens change (KI-02, What remains) | **Stopped.** The epoch is inside the signed Alive. |
| Invent reporter names to bring a suspicion down to the minimum timeout | **Stopped.** A reporter is a member with a certificate, and each confirmation is its own signature. |
| Claim names nobody holds, before their owners start or after their tombstones are reaped, and so choose rendezvous weights (KI-03, What remains) | **Stopped.** A name needs a certificate for it. |
| Fill the member table with invented names and point every node's probes at addresses it lists (KI-04, What remains) | **Stopped.** Names need certificates. |
| Send Acks for probes it never forwarded, keeping a dead member alive in a prober's view; with sequence numbers that are easy to guess, for every prober at once | **Stopped.** An Ack is signed by the probed member and bound to the prober's name, run, sequence number and unpredictable round challenge, and it passes through a relay unchanged. |
| Answer PingReqs falsely as a relay | **Narrowed.** As a relay the prober chose, it can drop the target's Ack or send a Nack of its own. It cannot forge the target's Ack, and the prober has two more relays, its direct probe and the TCP fallback. |
| Send direct messages and broadcasts in any member's name | **Stopped.** Each is signed by its sender. |
| Number a broadcast far ahead of a member's own, so nodes drop that member's next broadcasts as old copies | **Stopped.** Only the member signs its broadcasts. |
| Fill every node's broadcast queue with its own broadcasts | **Narrowed.** They are signed as its own, and a per-sender share of the queue keeps it from displacing others' (stage 4). |
| Stay a member until every other node rotates the cluster key | **Narrowed.** A revocation signed by the CA, handed to any one node, removes it from every node's view by gossip. It can still read traffic until the cluster key is rotated. |

What a single member can still do once signatures are required:

- **Accuse, under its own name.** It can suspect any member at its current incarnation. That is one reporter, so the suspicion runs at the maximum timeout and the member refutes it, at the price of a refutation and one step of local health. Stage 4 limits each signer to one new suspicion of a member per minimum timeout. Members acting together are one reporter each: c of them shorten the timeout as c confirmations do, and K + 1 of them (4 with the defaults) can have a node declare a member dead at once, as K + 1 honest reporters can.
- **Lie in push-pull.** A record that holds a member as Suspect or Dead is the sender's claim, not the member's statement, so it starts the unreported suspicion that a merge starts today (KP-05), which the member is told about and refutes.
- **Lie about itself.** Its liveness (it can answer probes while otherwise broken), its metadata and every address in it, its advertised address, its restarts and leaves, and its own observations as a relay. Signatures prove who said something, not that it is true. KI-05's guidance stands: treat names and metadata as claims.
- **Withhold.** Drop the gossip and broadcasts it should relay, and refuse to answer push-pulls. Gossip goes by many paths, so this slows spread rather than stopping it.
- **Read everything and move cluster time.** The cluster key still decrypts all traffic, and cluster time in nonces is not signed, so KI-06's What remains applies unchanged, as do KS-01's replays of whole packets inside the window and KS-09's traffic analysis.
- **Spend CPU.** A signature check costs twenty to fifty times what opening a datagram does (see [Cost](#5-cost)). A member can send statements that look new and carry bad signatures. An honest node never sends a bad signature, since it relays only what it verified, so the first bad signature in a packet drops the rest of the packet, and a budget of failed checks per second bounds the rest; past it, statements that need a check are dropped, and their next copies bring them again.

Plaintext mode stays unauthenticated: identities need encryption, and a config that asks for both is refused.

## 2. Identity

Signatures are only as good as the binding between a key and a name. The binding has to say which key may speak for a name, survive restarts, let the operator take the right away, and hold up when the first place a node hears of a member is a push-pull from the attacker.

### Options

**A. First sight.** A member sends its public key in its Alive, and a node binds the name to the first key it sees for it, until the member's tombstone is reaped.

- Nothing to set up: no CA, no files beyond today's.
- A key holder can still claim every name nobody holds yet and every name whose tombstone was reaped (KI-03 stays as it is). A node that joins through the attacker learns the attacker's keys for every name, and keeps them.
- A restart must keep its key, or it is a takeover that nobody can tell from a real one; so keys must be stored, and a node that loses its key loses its name until the cluster forgets it.
- Revocation is a key rotation on every node, as today.

**B. An allow-list.** Every node is configured with every member's name and public key.

- No certificates on the wire, and a lookup per check.
- Closes name claims completely, and a restart keeps working with the same key.
- Every node's configuration changes whenever a member joins the cluster for the first time, so it fits fixed fleets and nothing that scales: kinship's default names, a hostname and six random hex characters, are new at every start.
- Revocation is a configuration change on every node.

**C. A cluster CA.** The operator holds a CA key. A member's certificate binds its name to its public key for a period, signed by the CA, and nodes are configured with the CA's public key.

- Closes name claims and survives a join through the attacker: a certificate verifies wherever it came from.
- Members can join without touching anyone else's configuration, whatever issues their certificates.
- Revocation is one CA-signed message that any node can take and gossip.
- Costs a certificate per member on the wire when it first spreads (about 150 bytes), and an issuer the operator has to run: a CLI for fixed fleets, or a service that issues at start for scaling ones.

| | First sight | Allow-list | Cluster CA |
| --- | --- | --- | --- |
| Setup | none | every member's key on every node | one CA key, a certificate per member |
| New member | nothing | every node's configuration | a certificate |
| Name claims (KI-03) | stay | closed | closed |
| Joining through the attacker | trusts the attacker's keys | safe | safe |
| Restart | must keep its key | must keep its key | keeps its key, or gets a new certificate |
| Revocation | key rotation on every node | configuration on every node | one message, from any node |
| Wire | 32-byte key in each Alive | nothing | a certificate per member, once |
| Moves KI-01 to Fixed | no | yes | yes |

### Recommendation: a cluster CA

First sight cannot close KI-01, since it leaves the names the attacker reaches first, and an allow-list does not fit a cluster that scales. The CA does both jobs, and a fixed fleet can treat it as an allow-list by issuing every certificate once with the CLI.

**Certificate.** A new message type, 0x0B:

| Field | Size | Meaning |
| --- | --- | --- |
| version | 1 | 1 |
| issuer | 8 | first 8 bytes of BLAKE3 of the CA's public key |
| cluster | 8 | first 8 bytes of BLAKE3 of the cluster label, so a certificate from one cluster's CA cannot be used in another |
| name | 1 + n | the member's name, as NodeId |
| key | 32 | the member's Ed25519 public key |
| not_before, not_after | 8 + 8 | Unix seconds |
| signature | 64 | the CA's, over a context string and every field above |

That is 130 bytes plus the name: 147 with a 17-byte name and 194 with a 64-byte one. A certificate is named by its id, the first 8 bytes of BLAKE3 of its encoding.

**Trust anchors.** Config field `trust_anchors`: a list of CA public keys, so a CA can be rotated as cluster keys are: add the new one everywhere, reissue, remove the old one. A certificate is accepted if one anchor signed it, its cluster matches, and its validity covers the node's clock, give or take `certificate_skew` (5 minutes).

**Clock.** The core reads no clock. It estimates Unix time as the epoch it started with, which kinship-net takes from the wall clock, plus the time it has been running, and checks certificates against that. A node with epoch 0 cannot check them, so an identity needs an epoch, which every kinship-net node has.

**Names.** A certificate names one member exactly. A node with an identity must run under that name, so names have to be known when certificates are issued: stable names (a StatefulSet's pod names, a host's name) with certificates issued ahead, or any name with a certificate issued at start by a service the operator runs. A certificate for a pattern of names, such as `cache-*`, would let its holder claim any name it matches; it is left out, and could come later as an operator's choice.

**Restart.** A certificate binds a name, not a run. The epoch is a field of every signed Alive, so only the name's key can announce a new run, and a restart needs no new certificate: a restarted member signs its new epoch into its first Alive with the key it had, or with a new key and a new certificate. When a node holds two valid certificates for one name, the one with the later `not_before` wins, and statements signed under the other are refused once the newer one is known, so a process left running from an earlier run cannot outlive its successor's certificate.

**Distribution.** A member's certificate travels as a Certificate message ahead of its Alive when that Alive is new: its first Alive of a run, and the first after a new certificate. Relays pass the certificate on with the Alive for as long as they gossip it. Push-pull carries certificates too: a join's reply holds every certificate it has, and an anti-entropy reply holds those whose ids the request did not list beside its records. Everything else names the certificate by its 8-byte id. A node holds one certificate per member and the previous one during a renewal.

**Revocation.** A new message type, 0x0C, signed by a trust anchor: the issuer, the revoked certificate's id and the time until which to keep the revocation, the certificate's `not_after`. 88 bytes. Any node accepts one from the application (`cluster.identity.revoke(bytes)` in Python) and gossips it, and push-pull carries those a node holds until they expire. A node that holds a member under a revoked certificate declares it dead (MemberDead) and refuses its statements; a newer certificate brings it back. Revocations are kept until they expire, up to `max_revocations` (1,024), and only a CA key can make one, so an attacker cannot fill the list.

**The cluster key.** It stays, and stays shared. It keeps traffic confidential, carries cluster time and the replay window, and makes sure that only members cost a node a signature check. Once a member is revoked, rotating the cluster key is what stops it reading traffic, and that can wait until it is convenient; integrity no longer depends on it.

**Operator tools.** A sketch of the commands and config, for the Python package:

```bash
python -m kinship ca init --out ca.key                     # the CA's secret key, kept off the nodes
python -m kinship ca anchor ca.key                         # its public key, for trust_anchors
python -m kinship identity keygen --out cache-03.key       # a member's signing key
python -m kinship cert issue --ca ca.key --key cache-03.key --name cache-03 --days 90 > cache-03.cert
python -m kinship cert revoke --ca ca.key cache-03.cert > cache-03.revoked
```

```python
cfg = kinship.Config.lan(
    name="cache-03",
    keys=[cluster_key],
    signing_key=open("cache-03.key").read(),      # zeroized in Rust as cluster keys are (KS-07)
    certificate=open("cache-03.cert", "rb").read(),
    trust_anchors=[ca_anchor],
    require_signatures=False,                     # True once every node signs; see Rolling upgrade
)
```

The library exposes the same operations for an issuing service: `kinship.identity.issue(ca_key, name, member_key, days)`.

## 3. Which messages are signed

### Rules

1. **Every statement is signed by its author:** a member's statements about itself by the member, accusations by the accuser, probe answers by the member that answers.
2. **Relayed statements keep their author's signature.** Gossip and push-pull pass the bytes on unchanged, so the gossip queue and the member table keep the signature beside each rumour and record.
3. **A node relays only what it verified.** An honest node never sends a bad signature, which is what lets a receiver drop the rest of a packet at the first bad one.
4. **Check precedence before the signature.** A copy of a rumour a node already holds, or one that loses to what it holds, changes nothing and is dropped unchecked. Only news costs a check, so a node checks each rumour once, however many copies of it arrive.
5. **Statements are single-use where they could be replayed for effect.** Alives and Lefts are ordered by epoch and incarnation, accusations carry the signer's cluster time, probe answers are bound to the prober's sequence number, and a direct user message is bound to the nonce of the packet that carries it.
6. **Domain separation.** A signature covers a context string, `kinship v2 ` and the message type, the first 8 bytes of BLAKE3 of the cluster label, and the message body up to the signature, in its wire encoding, which has one encoding per value (design.md, Inner payload). Ed25519 signatures are deterministic, so signing draws no randomness, the core stays sans-IO, and the simulator still replays byte for byte.

### The messages

| Message | Signed by | Bound to | A receiver checks |
| --- | --- | --- | --- |
| Alive | the member | its epoch and incarnation; the certificate id it signs under | the certificate is valid for that name; then the signature |
| Left (Dead naming its own author) | the member | its epoch and incarnation | as Alive |
| Suspect | the reporter (`from`) | the suspected member's epoch and incarnation, and the reporter's cluster time `at` | the reporter is a live member it holds, not the suspect; `at` is inside the replay window; then the signature |
| Dead about another member | the declarer (`from`) | as Suspect | as Suspect; it then counts as a confirmation (below) |
| Ack | the probed member | the prober's name, epoch, sequence number and round challenge; its own name, epoch and certificate id | the Ack answers a probe this node is running, signed by its target |
| Nack | the relay | the prober's name, epoch, sequence number and round challenge; the target's name; its own name, epoch and certificate id | the relay is one this node asked in this round, once each |
| UserMessage | the sender | the nonce of the packet that carries it | the sender is a member it holds at that epoch, as now; then the signature |
| UserBroadcast | the sender | its epoch and sequence number | as now, then the signature, before it is delivered or relayed |
| PushPull record | the member, through its Alive or Left | as Alive or Left | each record as the Alive or Left it carries |
| Certificate | the CA | the cluster label | an anchor signed it, and it is valid now |
| Revocation | the CA | | an anchor signed it |

Ping and PingReq stay unsigned. A forged one can make a node send an Ack, a Ping or a Nack to a member it holds, which a key holder could send itself, and every answer that matters is now signed by whoever gives it. A relay sends its Ping only to the target address it holds for the target's name, and its Nack only to the address it holds for the requester's, which version 2 names in the PingReq.

### Suspect and Dead about another member

Any member with a valid certificate may sign a Suspect about another member, as today any member may report one; what changes is that a node can tell who said it.

- **A reporter is a signature.** A Suspect counts only if its signer is a live member the node holds, other than the suspect, and only once per signer. Invented names have no certificate and count for nothing.
- **A third party's Dead is a confirmation, not a death.** A Dead about member X from signer S, at the epoch the node holds and at or above its incarnation, adds S as a reporter of the node's suspicion of X, starting one if there was none, and is relayed as it came. The node declares X dead when its own timer runs out, or at once when its suspicion has at least min(K, n - 2) + 1 distinct signed reporters, S included, the count at which the Lifeguard timeout is already at its minimum. A real crash is confirmed by many probers before the first timer runs out, so the nodes that hear the first Dead have usually counted enough reporters already and declare it at once, as today; a node that missed them runs to its own timer.
- **Lifeguard is unchanged.** Suspicions shrink with independent confirmations, now independent signers; a merged suspicion still counts no reporter (KP-05); the buddy system puts the prober's signed Suspect ahead of its Ping; and a relay that knows a target left answers a PingReq with the target's own signed Left, which it kept with the tombstone.
- **Accusations expire.** Suspect and Dead carry `at`, the signer's cluster time when it signed. A node ignores one stamped below its replay floor, the window behind its cluster time, as it ignores packets stamped there. An accusation is gossiped for a few seconds, so this costs nothing, and it keeps a member that holds old accusations from replaying them after the fact.
- **A rate per signer (stage 4).** A signer may start one new suspicion of a member per minimum timeout; a Suspect from it at a higher incarnation within that time is dropped and counted under `accusations_dropped`. An honest prober suspects a member only after probing it, and a member that refuted is alive, so this delays nothing that matters; the Lifeguard sweep checks that.

**The partition-heal flap.** The `fix/partition-heal-flap` branch held no change to the core when this was written, only a simulator reproduction of the flap seen in the Compose demo on 2026-10-13: after a partition heals, the isolated node's Deads, at incarnations the healthy members never had to raise, are applied at once by nodes that hold those members Alive, and a healthy member is MemberDead for a moment. The two rules above should remove it in version 2: Deads older than the window are ignored, and fresher ones confirm a suspicion that the member refutes, rather than killing it. The fix for version 1 is not known yet. If it turns third-party Deads into suspicions, version 2 keeps that and adds the signature checks and the K + 1 shortcut. If it instead marks Deads from a node that just rejoined, version 2 can drop the marker, since `at` and the confirmation rule cover the case. Either way, the fix's simulator test should pass unchanged against version 2 in `require` mode, and stage 3 runs it there.

### Lifeguard's probes, through a relay

Today an Ack names only a sequence number, so a key holder can answer any prober's round, directly or as a relay.

- A Ping in version 2 carries its source's epoch and a fresh unpredictable 128-bit round challenge, and a relay's Ping also carries the requester's name, epoch and sequence number, from the PingReq. The relay preserves the original requester's challenge.
- The target signs its Ack over the requester's name, epoch, sequence number and challenge, its own name and epoch, and its certificate id. A direct Ack's requester is the source of the Ping. A relay forwards the target's signature unchanged, as it forwards the Ack today.
- The prober accepts an Ack only for the exact round and challenge it is running, signed by the target of that round, whichever path it came by. The challenge prevents a key holder from harvesting future-sequence Acks before the target crashes. Stage 2 must use a cryptographically secure source independently for each round.
- A relay signs its Nack over the same binding, and the prober counts at most one Nack from each relay it asked.

The direct probe, the indirect probes and the TCP fallback stay as they are, with the same timers. Nothing on the indirect path signs or carries an accusation: a relay's statements are its Ping, which needs no signature, and its Nack. Refusing forged Suspects and Deads therefore leaves indirect probes alone, and only the prober whose round failed signs the Suspect that follows.

### Push-pull state

A record is the member's own signed Alive, as the member signed it, with the certificate id; a Left record adds the member's signature of its Left. A record that holds a member as Suspect or Dead adds the incarnation it is suspected at, and is the sender's claim: it merges as an unreported suspicion, as today, and the member is told. Join replies carry certificates, as above. A record whose signature fails is dropped alone; the rest of the frame merges.

### Replays of signed statements

A signature does not expire, so a key holder that recorded a statement can put it into a fresh packet later, past the replay window that protects whole packets. Rule 5 makes that harmless for everything but one case: a member's last Alive, replayed after the member left or died and its tombstone was reaped, brings it back as a phantom that is probed, suspected and declared dead again. Today any key holder can do that without a recording. With signatures it needs one, and only until the member's certificate expires or is revoked. Closing it entirely would need Alives that expire too, re-signed by every member every few minutes, which costs a little gossip and changes nothing else; it is left as a decision.

## 4. Wire changes

### Version 2

Version 2 keeps version 1's header, AEAD and payload grammar. Every message keeps its version 1 fields first, and the signed messages append theirs. The table and cost estimates below are the original proposal's size sketch; [Stage 1 notes](ki01-stage1.md) specify the implemented fields, including certificate-specific bindings, explicit probe names and the accepted challenge. Stage 2 must remeasure these estimates before enabling traffic.

| Message | Appended in version 2 | Bytes added |
| --- | --- | --- |
| Alive | certificate id, signature | 72 |
| Suspect, Dead, Left | `at`, signature | 72 |
| Ack | the target's epoch, signature | 72 |
| Nack | the relay's name, signature | 66 to 129 |
| Ping | the source's epoch; on a relay's Ping, the requester's name, epoch and sequence number | 8; on a relay's, 15 to 77 more |
| PingReq | the requester's name and epoch | 10 to 73 |
| UserMessage, UserBroadcast | signature | 64 |
| PushPull record | certificate id, signature; Left: 72 more; Suspect or Dead: the suspected incarnation, 4 | 72 |
| Certificate (0x0B) | new | 147 with a 17-byte name, 194 with 64 |
| Revocation (0x0C) | new | 88 |

Epochs are always written in version 2: a node with an identity always has one, and the 8 bytes that a node without an epoch leaves out in version 1 are required. In a version 2 packet a signed message whose body ends before its signature is too short, a decode error, as a known message that is too short is today. A version 1 packet may carry the same bytes, and a 0.4 node reads it as it reads any message with appended fields: it takes the fields it knows and ignores the rest.

### Against today's datagram

A datagram is at most `udp_max_payload`, 1,400 bytes, and 1,350 of them are messages once the 48 bytes of header and tag and 2 for the message count are taken. With 17-byte names and 48 bytes of metadata, as in the measurements below:

| | Version 1 | Version 2 |
| --- | --- | --- |
| Ping | 49 bytes | 57 |
| Ack | 6 | 78 |
| Suspect or Dead | 50 | 122 |
| Alive | 90 | 162 |
| Suspects that fit beside a Ping | 26 | 10 |
| Alives that fit beside a Ping | 14 | 7 |

In steady state the measured clusters' datagrams were far from full: under 400 bytes at 100 nodes and in the calm 1,000-node cluster, and under 1,200 in the stressed one, where 0.24% of them would have overflowed with signatures. Signatures change what a datagram holds in bursts, when nodes have more rumours queued than fit. After every member changed its metadata at once, 7% of the datagrams were full at 100 nodes and 85% at 1,000, and version 2 would need about 1.8 times as many of those to send the same rumours, since an Alive grows from 90 bytes to 162. Packets take the least-sent rumours first, so every rumour's first copies go out before any retransmission, and reaching every node should slow by less than that; stage 2 measures it.

The limits the config validates move with the largest messages, a 64-byte name, an IPv6 address and 512 bytes of metadata:

| Limit, encrypted, default datagram | Version 1 | Version 2 |
| --- | --- | --- |
| Smallest `udp_max_payload` that fits the largest Alive beside the largest Ping | 821 bytes | 978 |
| Largest `max_meta_bytes` | 1,091 bytes | 934 |
| Largest `max_user_broadcast` | 1,108 bytes | 959 |
| Data in a direct message that fits one datagram | about 1,200 bytes | about 1,135 |
| Full push-pull frame, 8,192 members, with every certificate | about 5.0 MB | about 7.3 MB, under the 8 MiB `max_stream_frame` |

The defaults, 512 bytes of metadata and 256-byte broadcasts, fit with room to spare.

### Rolling upgrade from 0.4

Each node runs in one of three modes, chosen in its config and switchable at runtime:

| Mode | Signs | Requires | Speaks | Who it suits |
| --- | --- | --- | --- | --- |
| `off` (the default) | nothing | nothing | version 1 only, the bytes 0.4 sends | clusters without identities |
| `sign` | everything it authors | nothing: unsigned statements are accepted, bad signatures are not | versions 1 and 2 | the upgrade |
| `require` | everything it authors | a valid signature on every signed message | version 2 only | the goal |

Version negotiation, which design.md describes and review.md notes is not implemented, becomes real and per recipient: each node seals a packet for its recipient at the highest version both speak, from the `vmin` and `vmax` in the recipient's Alive, and seals at its own lowest version for an address it holds no member at, such as the requester of a PingReq. Seeds are such addresses too, so a node with an identity tries its join at version 2 first and at version 1 on its next attempt.

The upgrade, one node at a time throughout:

1. **Every node to the release with version 2, in mode `off`.** It sends what 0.4 sends, and the simulator's pinned SWIM trace stays the same.
2. **Certificates, then mode `sign`, node by node.** A signing node advertises versions 1 to 2, sends version 2 to the members that advertise it and version 1, with the appended fields, to the rest. A 0.4 node, or one in mode `off`, skips the appended fields and the two new message types, so it keeps working, but the rumours it relays have lost their signatures, which is why `sign` requires nothing. `stats()` counts the members a node holds without a valid certificate as `unsigned_members`.
3. **Mode `require`, once `unsigned_members` is 0 on every node.** A requiring node advertises version 2 only and refuses version 1 packets at the header, before decryption, as it refuses a key it does not hold (KS-03), so a node still on 0.4 or in `off` can no longer reach it. Nodes in `sign` and `require` work together, since everything is signed by then.

Rolling back is the same steps in reverse. KI-01 is closed on a node once it runs in `require`, and for the cluster once every node does.

## 5. Cost

### CPU

ed25519-dalek 3.0.0 (BSD-3-Clause), from the dalek-cryptography project, with its default features. It brings curve25519-dalek 5, sha2 0.11, digest 0.11, ed25519 3, signature 3 and subtle into the tree, shares crypto-common with chacha20poly1305 0.11, adds no second version of any crate kinship-proto already uses, and passes `cargo deny check advisories bans sources`. Its signatures are deterministic (RFC 8032), and `verify_strict` refuses the small-order keys and non-canonical encodings that plain `verify` lets through.

Measured on the 4-core Ryzen 5 3550H laptop the tuning sweep used, in a release build, single thread, median of 15 batches:

| Operation | Time |
| --- | --- |
| Sign a 120-byte statement | 29 µs |
| Sign a 700-byte statement | 32 µs |
| `verify_strict`, either size, good or bad signature | 82 µs |
| Decompress a public key (once per certificate, then cached) | 6 µs |
| kinship-proto `open` of a 99-byte datagram, for comparison | 1.5 µs |
| kinship-proto `open` of a full 1,399-byte datagram | 4.0 µs |

Building with `target-cpu=native` saved about 10%.

Rule 4 is what keeps this cheap: a node checks each statement once, however many copies arrive. In the simulated clusters below a node checked 1 to 14 signatures a second, in a calm cluster mostly the Acks to its own probes, and signed about one, mostly its own Acks. The counts come from the bandwidth runs below, which counted, for each node, the Acks it received and the first copy of each statement it saw:

| Cluster | Signs per node per second | Checks per node per second | CPU per node |
| --- | --- | --- | --- |
| 100 nodes, steady, one crash | 1.0 | 1.1 | 0.01% of a core |
| 100 nodes, 1% loss, one starved node | 1.2 | 2.2 | 0.02% |
| 1,000 nodes, steady, one crash | 1.0 | 1.1 | 0.01% |
| 1,000 nodes, burst after every member's metadata changed | 1.0 | 4.7 | 0.04% |
| 1,000 nodes, 1% loss, 10 starved nodes | 1.2 | 10.0 | 0.08% |
| 1,000 nodes, 1% loss, 10 starved nodes, burst | 1.2 | 14.1 | 0.12% |

Per packet, a datagram that carries nothing new costs what it does today; one with news costs about 80 µs per new statement. A node joining a cluster checks every member's certificate and Alive once: 17 ms at 100 members and 170 ms at 1,000, and with the defaults one push-pull frame costs at most that, since it admits at most `max_new_members_per_packet` (1,024) new members (KI-04). A node configured to admit more per frame pays in proportion, about 3.3 s for KI-04's 20,000 members in one frame, so stage 2 spreads the checks of a large frame over several inputs, or looks at batch verification, which needs random coefficients the core would have to take from its nonce key.

### Bandwidth

Measured in kinship-sim by a throwaway test beside `tests/tuning.rs`, not committed: a 0.4 cluster on `lan()`, sealed with a key as in production, 17-byte names (`cache-0042-3f9a1c`), 48 bytes of metadata set by every member between 1 and 5 s, a crash at 240 s, 330 s in all. It opened every packet each node sent and added what version 2 adds to each message by the table in [Version 2](#version-2). The steady window is 150 to 330 s; the burst window, 5 to 150 s, holds the spreading of every member's new metadata at once. The stressed cluster adds 1% loss on every link and starves 1% of the nodes, which read every packet 0.5 to 2.5 s late, as the tuning sweep's cells do. Seeds 0 and 1 at 100 nodes, seed 0 at 1,000; they agreed to within 2%.

| Cluster, window | Today, bytes per node per second (UDP + TCP) | Version 2 adds | Of which push-pull |
| --- | --- | --- | --- |
| 100 nodes, steady | 845 (194 + 650) | 628, +74% | 517 |
| 100 nodes, burst | 972 (372 + 600) | 727, +75% | 478 |
| 100 nodes, stress | 1,782 (1,128 + 654) | 1,273, +71% | 519 |
| 1,000 nodes, steady | 6,715 (211 + 6,504) | 5,325, +79% | 5,200 |
| 1,000 nodes, burst | 15,803 (9,801 + 6,001) | 12,377, +78% | 4,820 |
| 1,000 nodes, stress | 13,051 (6,539 + 6,512) | 11,742, +90% | 5,205 |
| 1,000 nodes, stress, burst | 21,571 (15,566 + 6,005) | 18,526, +86% | 4,824 |

Where the bytes go:

- **Push-pull** is most of it. Each record grows from about 90 bytes to 162, and a node sends its whole table every `push_pull_interval`, so this part grows with the cluster: 517 bytes per node per second at 100 nodes, 5,200 at 1,000.
- **Acks** add 72 bytes a second per node, one per probe. Leaving them unsigned would save 9% of today's bytes at 100 nodes and give back the blanket-Ack attack.
- **Rumours** add 72 bytes per Suspect, Dead and Alive sent. That matters under stress, where false suspicions of the starved nodes and their refutations keep the gossip busy: at 1,000 nodes they add 6.5 KB/s per node, as much as push-pull does.
- **Certificates** are paid once per member and run: a joining member's certificate rides its first Alive, about 150 bytes for each of the retransmit limit's sends at every node, 12 at 100 nodes or about 180 KB across the cluster, and a join's reply carries every certificate, 150 KB at 1,000 members.

Two changes could win most of it back, and neither needs signatures to be worth doing: push-pull that exchanges a digest of each record (name, epoch, incarnation and state, about 20 bytes) and sends whole records only where the two sides differ, which would cut today's push-pull bytes as well; and a longer `push_pull_interval` at large sizes. They are not part of this plan.

### Memory

72 bytes per member for the signature and certificate id, about 150 for its certificate, 72 per queued rumour, and the revocation list: under 3 MB for a full table of 8,192 members.

## 6. Staged plan

Each stage is one or more pull requests that leave main releasable. Nothing changes on the wire until stage 2, and nothing is enforced until stage 3.

**Stage 1: kinship-proto (primitives and explicit codec support implemented).**

- `kinship_proto::identity`: `SigningKey` (heap-allocated, zeroized, compared in constant time and never printed, as `Key` is), `PublicKey`, `Certificate` and `Revocation` with strict decoders and canonical encoders, and the signed-bytes construction of rule 6.
- The appended fields of version 2 and the two new message types, highest codec version `MAX_WIRE_VERSION` 2, and explicit `Codec` entry points sealing at a version the caller picks and opening versions 1 and 2. `WIRE_VERSION`, existing codec methods and the runtime's exported `WIRE_VERSION` remain 1. [Stage 1 notes](ki01-stage1.md) pin the completed grammar and API isolation.
- Tests: round trips and one-encoding-per-value property tests for every new field; RFC 8032 test vectors through the wrapper; certificates that are expired, not yet valid, for another cluster, signed by an unknown anchor, or truncated, all refused; a version 2 payload, stamped version 1, parsed by the released kinship-proto 0.4.0 as a dev-dependency, with every known field equal and no decode error; the fuzz targets `decode_payload` and `decode_datagram` given version 2 inputs, and a new `decode_certificate`. `cargo deny` stays clean.

**Stage 2: kinship-core, mode `sign` (Stages 2a and 2b implemented).**

- Status: split into 2a, 2b and 2c ([Stage 2 notes](ki01-stage2.md)). Stage 2a is implemented: identity in `Config`, signatures and certificates in the member table, the gossip queue and push-pull, signing of every authored Alive, Left, Suspect and Dead, checks after precedence, certificate distribution, per-recipient versions and the three counters, with the per-message tests, a simulator cluster of 0.4 and signing nodes, and a pinned trace in `sign`. Stage 2b is implemented: a challenge per round from a ChaCha20 stream of the nonce key, version 2 Pings, PingReqs, Acks and Nacks to members held signed, directly, through relays and over TCP, Acks and Nacks signed over the round's binding and taken only for the exact round, signed rumours on the probe packets, and signed direct messages, bound to their packet's nonce, and broadcasts, with the per-message tests, the harvesting case at runtime and user messages in the mixed simulator cluster. Stage 2c (the 1,000-seed sweeps, the signed tuning comparison and the remeasured costs) remains.
- Identity in `Config` and `Identity`; the member table, the gossip queue and push-pull keep signatures and certificates; every authored statement is signed; every received signature is checked after precedence; certificates spread as in [Distribution](#recommendation-a-cluster-ca); per-recipient versions; the Ack and Nack bindings; the new counters `signatures_invalid`, `unsigned_members` and `certificates_refused`.
- Tests: unit tests per message for a good signature, a bad one, a missing one in `sign`, the wrong signer and a revoked or expired certificate; the 1,000-seed sweeps (`swim`, `sync`, `epoch`, `usermsg`, `failure`, `keyring`) with every node in `sign`; a mixed cluster of the released 0.4 core and version 2 nodes in `sign`, in the simulator as `usermsg` runs 0.3 beside 0.4 today, converging and detecting crashes as an all-0.4 cluster does; the pinned SWIM trace unchanged in `off`, and a second pinned trace in `sign`, which deterministic signatures allow; a `signed` variant of the tuning sweep at 50, 200 and 1,000 nodes, reporting bandwidth, detection latency and false deaths against `lan()`.

**Stage 3: mode `require`, and the accusation rules.**

- Refusing unsigned statements and version 1 packets; third-party Deads as confirmations with the K + 1 shortcut; `at` on accusations; the first bad signature drops the rest of its packet.
- Tests: `open_findings::ki01_a_member_declares_any_node_dead_at_once` turned into a test that asserts the fix, as KI-02 to KI-06's were: a member's sealed and signed Dead makes no node report MemberDead for a live member. A rogue node in kinship-sim, holding the cluster key and its own certificate, that every second forges Deads, Lefts, Alives with new metadata and later epochs, Suspects under invented and real names, Acks for every sequence number of every node, push-pull frames full of Dead and Left records, and user messages and broadcasts in other members' names, over 1,000 seeds: no live member is ever reported dead or left, no forged metadata or message is delivered, and a crashed member is still declared dead within the analytic bound. The detection sweep and `detection_tail` in `require`, compared with `off`, to measure what the K + 1 rule costs at the tail. The partition-heal reproduction from `fix/partition-heal-flap` in `require`: no healthy member is ever reported dead.

**Stage 4: revocation, renewal and limits.**

- Revocation messages, `certificate_skew`, renewing a certificate at runtime (`cluster.identity.renew(cert)`, re-signing the node's Alive at a new incarnation), several trust anchors, the per-signer rate of suspicions, the per-sender share of the broadcast queue, and the budget of failed checks per second.
- Tests: a revoked member is MemberDead on every node within the time a rumour takes to spread, and its statements are refused; an expired certificate is refused at its `not_after`, give or take the skew; a renewal mid-run raises no suspicion; a CA rotation with two anchors keeps every member; the rogue node's own suspicions every second raise no false death, and its broadcasts never displace others'; the Lifeguard grid in `require` against `off`, for the rate per signer.

**Stage 5: bindings, tools and documentation.**

- kinship-net and the `kinship` facade take the identity; Python `Config` fields `signing_key`, `certificate`, `trust_anchors` and `require_signatures`, with KS-07's handling of key bytes; `python -m kinship ca`, `identity` and `cert` commands and `kinship.identity`; `stats()` and `kinship.metrics` export the new counters; README, design.md (wire format, the incarnation table with accusations, configuration), SECURITY.md and the Compose demo, with a CA and a certificate per node.
- Tests: pytest for config validation, the CLI and a three-node cluster that rejects a forged Dead; a chaos scenario on real sockets with a rogue node, built with the test-hooks feature, under 1 to 5% loss: no node may declare a live member dead.

**What moves KI-01 from Accepted to Fixed.** Stage 3 merged, with the rogue-node sweep and the KI-01 test running in CI, and stages 4 and 5 merged, so that an operator can issue, renew and revoke certificates and turn `require_signatures` on from Python. KI-01's entry then reads, as KS-04's does for plaintext: Fixed with member identities in mode `require`; without identities the cluster trusts every key holder as before. Its What remains lists [what a member can still do](#1-threat-model), and KI-03's and KI-04's What remains drop the parts about names. Until then KI-01 stays Accepted, and each stage's pull request updates SECURITY.md with what it changed.

## Decisions

**Accepted by Nikola on 2026-10-16.** The following selections resolve the alternatives listed below:

1. Use a cluster CA to bind member names to signing keys.
2. Treat a third party's Dead as a confirmation, with the proposed K + 1 signed-reporter shortcut. Validate it against the partition-heal fix during implementation.
3. Sign Acks and preserve the target's signature through indirect probes.
4. Accept the estimated 71% to 90% bandwidth increase for the opt-in mode; digest push-pull is not a prerequisite.
5. Use wire version 2 with per-recipient negotiation.
6. Accept replay of a departed member's last Alive until its certificate expires; periodic re-signing is not required by this plan.
7. Ship as an opt-in feature in a 1.x minor release after 1.0.
8. Keep internal crates on 0.x and pin their exact versions from the stable kinship facade, as recorded in [the stability policy](stability.md).
9. **Stage 1 security correction, accepted on 2026-10-16:** add a fresh unpredictable 128-bit challenge per probe round, carried unchanged through Ping/PingReq/Ack/Nack and covered by signed replies. Name, epoch and predictable sequence binding alone lets a key holder harvest Acks to future rounds from a live target and replay them after it crashes. Stage 2 must generate and match the challenge; Stage 1 implements only its wire fields and canonical signature binding.

The original alternatives and their tradeoffs are retained for context:

1. **The binding.** A cluster CA, as recommended, or an allow-list, which is simpler for fixed fleets but cannot follow a cluster that scales. First sight cannot close KI-01.
2. **A third party's Dead.** A confirmation, with a node declaring death at once from K + 1 signed reporters, as proposed; or Deads only from a node's own timer, which is simpler and costs detection time at the tail. Either way it should agree with what `fix/partition-heal-flap` does for version 1.
3. **Signed Acks.** About 72 bytes a second per node, 9% of today's bytes at 100 nodes and 1% at 1,000, to stop a key holder from keeping dead members alive in every prober's view. Unsigned Acks would leave that open.
4. **The bandwidth.** 71% to 90% more bytes per node, most of it in push-pull and, under stress, in rumours: accept it for an opt-in mode, or add digest push-pull before or with stage 2.
5. **The header version.** A real version 2 with per-recipient negotiation, as proposed, which gives `require` a cheap header check; or version 1 throughout, with the modes alone deciding, which is simpler and gives up that check.
6. **Expiring Alives.** Leave the replay of a departed member's last Alive bounded by certificate lifetimes, or have members re-sign their Alive every few minutes.
7. **When.** After 1.0, as an opt-in in a 1.x minor release, which `docs/stability.md` allows; or before, which would let 1.0 promise it.
