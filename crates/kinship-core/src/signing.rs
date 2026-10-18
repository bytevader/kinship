//! Per-member keys, mode `sign`: KI-01 Stage 2a (`docs/ki01-stage2.md`).
//!
//! A node configured with [`Signatures::Sign`] signs every Alive, Left, Suspect and Dead it
//! authors, checks the signature of every one it receives that would change its view, keeps the
//! proofs beside its members and rumours, and forwards them unchanged to members that speak
//! wire version 2. It accepts unsigned statements, from version 1 packets, as the plan's mode
//! `sign` says, but never a signed statement whose check failed.
//!
//! Precedence comes before the signature (rule 4): a statement that changes nothing costs no
//! check. Push-pull records spend at most [`CHECKS_PER_INPUT`] checks per input, and what is
//! left of a large frame waits, copied out of it, for the inputs that follow.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use kinship_proto::identity::{Certificate, CertificateId, PublicKey, Signature, SigningKey};
use kinship_proto::v2::{self, RecordState, SignedAlive};
use kinship_proto::{Alive, Dead, Suspect};

use crate::Node;
use crate::broadcast::id;
use crate::member::{Admission, Life, at_least, life, newer};
use crate::time::Instant;

/// How far a certificate's validity may be from this node's clock, on either side, in seconds.
/// Fixed in Stage 2a; Stage 4 makes it configurable.
pub const CERTIFICATE_SKEW_SECS: u64 = 300;

/// Signature checks one input may spend on push-pull records, about 5 ms at the 82 µs a check
/// took on the laptop of the plan's measurements.
pub(crate) const CHECKS_PER_INPUT: usize = 64;

/// Whether this node has a member identity (KI-01), and what it does with it. Experimental:
/// the feature is planned for an opt-in release after 1.0.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Signatures {
    /// No identity: the node signs nothing, checks nothing and speaks wire version 1 only,
    /// sending the bytes 0.4 sends.
    #[default]
    Off,
    /// Signs every Alive, Left, Suspect and Dead this node authors, checks those it receives,
    /// and speaks wire versions 1 and 2. Unsigned statements are still accepted; statements
    /// whose signature or certificate fails are not.
    Sign(Credentials),
}

impl Signatures {
    pub fn credentials(&self) -> Option<&Credentials> {
        match self {
            Self::Sign(c) => Some(c),
            Self::Off => None,
        }
    }
}

/// A member's signing key, its certificate and the CA keys it trusts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub signing_key: SigningKey,
    /// This node's certificate, as [`Certificate::encode`] writes it. It must name this node,
    /// carry `signing_key`'s public key, be signed by one of `trust_anchors` for this cluster's
    /// label, and be valid at the node's clock: its epoch plus the time it has run.
    pub certificate: Vec<u8>,
    /// Public keys of the cluster CAs. A certificate is accepted when one of them signed it.
    pub trust_anchors: Vec<PublicKey>,
}

/// A certificate this node holds for a member, checked when it arrived: the bytes it came in,
/// and the parsed key and validity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeldCert {
    pub id: CertificateId,
    pub bytes: Vec<u8>,
    pub key: PublicKey,
    pub not_before: u64,
    pub not_after: u64,
}

impl HeldCert {
    pub fn new(c: &Certificate<'_>) -> Self {
        Self {
            id: c.id(),
            bytes: c.encode(),
            key: c.key(),
            not_before: c.not_before(),
            not_after: c.not_after(),
        }
    }

    /// Whether the certificate is valid at Unix second `now`, give or take the skew.
    pub fn is_current(&self, now: u64) -> bool {
        now.saturating_add(CERTIFICATE_SKEW_SECS) >= self.not_before
            && now.saturating_sub(CERTIFICATE_SKEW_SECS) < self.not_after
    }

    pub fn certificate(&self) -> Option<Certificate<'_>> {
        Certificate::decode(&self.bytes).ok()
    }
}

/// The signature of a member's Alive: the incarnation it was signed at, which a suspicion at a
/// higher one does not change, and its certificate id and signature. The rest of the signed
/// bytes are the member's own fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AliveProof {
    pub inc: u32,
    pub cert: CertificateId,
    pub sig: Signature,
}

/// The signature of a Suspect or Dead: the signer's cluster time, its certificate id and the
/// signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AccusationProof {
    pub at: u64,
    pub cert: CertificateId,
    pub sig: Signature,
}

/// A member's signed Left, kept with its tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeftProof {
    pub inc: u32,
    pub epoch: u64,
    pub proof: AccusationProof,
}

/// A checked signature for an Alive about to be applied.
#[derive(Debug, Clone)]
pub(crate) struct SignedBy {
    pub proof: AliveProof,
    /// The certificate it was checked under, when the packet brought it: the member's from now
    /// on.
    pub cert: Option<HeldCert>,
    /// Whether the packet carried the certificate, so that a relay passes it on.
    pub carried: bool,
    /// Whether it came in a version 2 push-pull, whose sender spreads this node's own record
    /// signed as well, so that the member needs no announcement from this node.
    pub pulled: bool,
}

/// Certificates a packet carries, with their ids, parsed but not yet checked.
pub(crate) type PacketCerts<'a> = [(CertificateId, Certificate<'a>)];

pub(crate) fn packet_certs<'a>(
    certs: impl Iterator<Item = Certificate<'a>>,
) -> Vec<(CertificateId, Certificate<'a>)> {
    certs.map(|c| (c.id(), c)).collect()
}

/// The version 2 form of an Alive.
pub(crate) fn signed_alive<'a>(a: &Alive<'a>, proof: &AliveProof) -> v2::Message<'a> {
    v2::Message::Alive(SignedAlive {
        alive: Alive {
            inc: proof.inc,
            ..*a
        },
        certificate_id: proof.cert,
        signature: proof.sig,
    })
}

pub(crate) fn signed_suspect<'a>(s: &Suspect<'a>, p: &AccusationProof) -> v2::Message<'a> {
    v2::Message::Suspect {
        suspect: *s,
        at: p.at,
        certificate_id: p.cert,
        signature: p.sig,
    }
}

pub(crate) fn signed_dead<'a>(d: &Dead<'a>, p: &AccusationProof) -> v2::Message<'a> {
    v2::Message::Dead {
        dead: *d,
        at: p.at,
        certificate_id: p.cert,
        signature: p.sig,
    }
}

/// What mode `sign` adds to a node.
#[derive(Debug)]
pub(crate) struct Keys {
    /// This node's own certificate.
    pub own: HeldCert,
    /// When the node started, and its epoch then: the clock certificates are checked against.
    started: Instant,
    start_ms: u64,
    /// One certificate per member, by name: the one its applied Alive was signed under.
    pub certs: BTreeMap<String, HeldCert>,
    /// Push-pull records left over from frames whose checks did not fit their input.
    pub deferred: VecDeque<Deferred>,
    pub deferred_len: usize,
    /// Checks this input may still spend on push-pull records.
    pub checks_left: usize,
}

impl Keys {
    pub fn new(own: HeldCert, started: Instant, start_ms: u64) -> Self {
        Self {
            own,
            started,
            start_ms,
            certs: BTreeMap::new(),
            deferred: VecDeque::new(),
            deferred_len: 0,
            checks_left: CHECKS_PER_INPUT,
        }
    }

    /// This node's estimate of Unix time in seconds: its epoch, the wall clock in milliseconds
    /// when it started, plus the time it has been running.
    pub fn unix_now(&self, now: Instant) -> u64 {
        let ran = now.saturating_duration_since(self.started).as_millis();
        let ran = u64::try_from(ran).unwrap_or(u64::MAX);
        self.start_ms.saturating_add(ran) / 1000
    }

    /// The certificate held for `name` with id `cert`, this node's own included.
    pub fn held(&self, me: &str, name: &str, cert: CertificateId) -> Option<&HeldCert> {
        if name == me && self.own.id == cert {
            return Some(&self.own);
        }
        self.certs.get(name).filter(|c| c.id == cert)
    }
}

/// A push-pull record copied out of its frame, to be handled on a later input.
#[derive(Debug)]
pub(crate) struct PendingRecord {
    name: String,
    inc: u32,
    addr: SocketAddr,
    meta: Vec<u8>,
    vmin: u8,
    vmax: u8,
    epoch: u64,
    cert: CertificateId,
    sig: Signature,
    state: RecordState,
}

impl PendingRecord {
    fn new(r: &v2::Record<'_>) -> Self {
        let a = &r.alive.alive;
        Self {
            name: a.node.as_str().to_owned(),
            inc: a.inc,
            addr: a.addr,
            meta: a.meta.to_vec(),
            vmin: a.vmin,
            vmax: a.vmax,
            epoch: a.epoch,
            cert: r.alive.certificate_id,
            sig: r.alive.signature,
            state: r.state,
        }
    }

    fn record(&self) -> v2::Record<'_> {
        v2::Record {
            alive: SignedAlive {
                alive: Alive {
                    inc: self.inc,
                    node: id(&self.name),
                    addr: self.addr,
                    meta: &self.meta,
                    vmin: self.vmin,
                    vmax: self.vmax,
                    epoch: self.epoch,
                },
                certificate_id: self.cert,
                signature: self.sig,
            },
            state: self.state,
        }
    }
}

/// What is left of one push-pull frame: its records, the certificates it carried and its
/// admission budget.
#[derive(Debug)]
pub(crate) struct Deferred {
    records: VecDeque<PendingRecord>,
    certs: Vec<Vec<u8>>,
    budget: Admission,
}

/// What a received statement needs before it can be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum News {
    /// It changes nothing: dropped unchecked.
    None,
    /// A member new to this node with no room for it: refused and counted, unchecked.
    Refused,
    /// It changes this node's view: checked, then applied.
    Check,
}

impl Node {
    fn signing_key(&self) -> Option<&SigningKey> {
        self.cfg.signatures.credentials().map(|c| &c.signing_key)
    }

    fn own_cert(&self) -> Option<CertificateId> {
        self.keys.as_ref().map(|k| k.own.id)
    }

    fn sign(&self, msg: &v2::Message<'_>) -> Option<Signature> {
        let bytes = msg.signed_bytes(self.cfg.cluster.as_bytes(), None).ok()?;
        Some(self.signing_key()?.sign(&bytes))
    }

    /// The signature of this node's own Alive `a`, when it signs.
    pub(crate) fn sign_alive(&self, a: &Alive<'_>) -> Option<AliveProof> {
        let mut proof = AliveProof {
            inc: a.inc,
            cert: self.own_cert()?,
            sig: [0; 64],
        };
        proof.sig = self.sign(&signed_alive(a, &proof))?;
        Some(proof)
    }

    /// The signature of a Suspect this node authors, stamped with its cluster time.
    pub(crate) fn sign_suspect(&self, s: &Suspect<'_>) -> Option<AccusationProof> {
        let mut proof = AccusationProof {
            at: self.out.stamp,
            cert: self.own_cert()?,
            sig: [0; 64],
        };
        proof.sig = self.sign(&signed_suspect(s, &proof))?;
        Some(proof)
    }

    /// The signature of a Dead this node authors, its own Left included.
    pub(crate) fn sign_dead(&self, d: &Dead<'_>) -> Option<AccusationProof> {
        let mut proof = AccusationProof {
            at: self.out.stamp,
            cert: self.own_cert()?,
            sig: [0; 64],
        };
        proof.sig = self.sign(&signed_dead(d, &proof))?;
        Some(proof)
    }

    /// Signs this node's Alive again after it changed.
    pub(crate) fn resign_local(&mut self) {
        if self.keys.is_none() {
            return;
        }
        let me = &self.local;
        let a = Alive {
            inc: me.member.incarnation,
            node: id(&me.member.name),
            addr: me.member.addr,
            meta: &me.member.meta,
            vmin: me.vmin,
            vmax: me.vmax,
            epoch: me.member.epoch,
        };
        self.local.proof = self.sign_alive(&a);
    }

    /// The bytes of the certificate `name` signs under now, if this node holds it.
    pub(crate) fn cert_bytes(&self, name: &str, cert: CertificateId) -> Option<Vec<u8>> {
        let keys = self.keys.as_ref()?;
        keys.held(&self.local.member.name, name, cert)
            .map(|c| c.bytes.clone())
    }

    /// Checks `msg`, signed by `signer` under certificate `cert`. The certificate is the one
    /// this node holds for the signer, or one that `packet` carries, which is then checked
    /// against the trust anchors, the cluster and the clock. Counts what fails. `None` if the
    /// check failed or the certificate is not at hand.
    pub(crate) fn check(
        &mut self,
        msg: &v2::Message<'_>,
        signer: &str,
        cert: CertificateId,
        packet: &PacketCerts<'_>,
    ) -> Option<SignedBy> {
        let carried = packet.iter().any(|(id, _)| *id == cert);
        let anchors = &self.cfg.signatures.credentials()?.trust_anchors;
        let label = self.cfg.cluster.as_bytes();
        let keys = self.keys.as_mut()?;
        let now = keys.unix_now(self.now);
        let (key, new) = match keys.held(&self.local.member.name, signer, cert) {
            Some(held) if !held.is_current(now) => {
                self.metrics.certificates_refused += 1;
                return None;
            }
            Some(held) => (held.key, None),
            None => {
                let (_, c) = packet.iter().find(|(id, _)| *id == cert)?;
                keys.checks_left = keys.checks_left.saturating_sub(1);
                if c.name().as_str() != signer
                    || c.verify(anchors, label, now, CERTIFICATE_SKEW_SECS)
                        .is_err()
                {
                    self.metrics.certificates_refused += 1;
                    return None;
                }
                (c.key(), Some(HeldCert::new(c)))
            }
        };
        keys.checks_left = keys.checks_left.saturating_sub(1);
        let signature = msg.signature()?;
        let good = msg
            .signed_bytes(label, None)
            .is_ok_and(|bytes| key.verify(&bytes, signature).is_ok());
        if !good {
            self.metrics.signatures_invalid += 1;
            return None;
        }
        let inc = match msg {
            v2::Message::Alive(a) => a.alive.inc,
            _ => 0,
        };
        Some(SignedBy {
            proof: AliveProof {
                inc,
                cert,
                sig: *signature,
            },
            cert: new,
            carried,
            pulled: false,
        })
    }

    /// Makes `cert` the certificate `name` signs under, if it brought one, and returns the
    /// bytes of the one it signs under now.
    pub(crate) fn bind_cert(&mut self, name: &str, signed: &SignedBy) -> Option<Vec<u8>> {
        let keys = self.keys.as_mut()?;
        if name != self.local.member.name {
            if let Some(cert) = &signed.cert {
                keys.certs.insert(name.to_owned(), cert.clone());
            }
        }
        self.cert_bytes(name, signed.proof.cert)
    }

    /// A signed Alive from a version 2 packet.
    pub(crate) fn on_signed_alive(
        &mut self,
        now: Instant,
        sa: &SignedAlive<'_>,
        packet: &PacketCerts<'_>,
        budget: &mut Admission,
        pulled: bool,
    ) {
        let a = &sa.alive;
        match self.alive_news(a, budget) {
            News::None => {}
            News::Refused => self.metrics.members_refused += 1,
            News::Check => {
                let msg = v2::Message::Alive(*sa);
                if let Some(signed) = self.check(&msg, a.node.as_str(), sa.certificate_id, packet) {
                    let signed = SignedBy { pulled, ..signed };
                    self.on_alive(now, a, budget, Some(signed));
                }
            }
        }
    }

    /// A signed Suspect from a version 2 packet.
    pub(crate) fn on_signed_suspect(
        &mut self,
        now: Instant,
        msg: &v2::Message<'_>,
        packet: &PacketCerts<'_>,
    ) {
        let v2::Message::Suspect {
            suspect,
            at,
            certificate_id,
            signature,
        } = *msg
        else {
            return;
        };
        if !self.suspect_news(&suspect)
            || self
                .check(msg, suspect.from.as_str(), certificate_id, packet)
                .is_none()
        {
            return;
        }
        let proof = AccusationProof {
            at,
            cert: certificate_id,
            sig: signature,
        };
        self.on_suspect(now, &suspect, Some(proof));
    }

    /// A signed Dead from a version 2 packet: a member's Left, or a third party's declaration,
    /// which still kills at once in Stage 2a.
    pub(crate) fn on_signed_dead(
        &mut self,
        now: Instant,
        msg: &v2::Message<'_>,
        packet: &PacketCerts<'_>,
    ) {
        let v2::Message::Dead {
            dead,
            at,
            certificate_id,
            signature,
        } = *msg
        else {
            return;
        };
        if !self.dead_news(&dead)
            || self
                .check(msg, dead.from.as_str(), certificate_id, packet)
                .is_none()
        {
            return;
        }
        let proof = AccusationProof {
            at,
            cert: certificate_id,
            sig: signature,
        };
        self.on_dead(now, &dead, Some(proof));
    }

    /// Handles every message of an authenticated version 2 payload: the certificates it
    /// carries, then its statements in order. Stage 2a sends no probe, user message or
    /// revocation at version 2, and ignores those it receives.
    pub(crate) fn process_v2(&mut self, payload: &v2::Payload<'_>) {
        let now = self.now;
        let mut budget = self.admission();
        let certs = packet_certs(payload.iter().filter_map(|m| match m {
            v2::Message::Certificate(c) => Some(c),
            _ => None,
        }));
        for msg in payload.iter() {
            match msg {
                v2::Message::Alive(sa) => {
                    self.on_signed_alive(now, &sa, &certs, &mut budget, false)
                }
                v2::Message::Suspect { .. } => self.on_signed_suspect(now, &msg, &certs),
                v2::Message::Dead { .. } => self.on_signed_dead(now, &msg, &certs),
                _ => {}
            }
        }
    }

    /// What a version 2 push-pull record needs: each record as the Alive or Left it carries,
    /// and a Suspect or Dead record, the sender's claim, as the merged suspicion it starts,
    /// after its Alive is checked.
    fn record_news(&self, r: &v2::Record<'_>, budget: &Admission) -> News {
        let a = &r.alive.alive;
        let news = match r.state {
            RecordState::Alive => return self.alive_news(a, budget),
            RecordState::Left { inc, .. } => self.dead_news(&Dead {
                inc,
                node: a.node,
                from: a.node,
                epoch: a.epoch,
            }),
            RecordState::Suspect { inc } | RecordState::Dead { inc } => {
                self.merged_news(a.node.as_str(), inc, a.epoch)
            }
        };
        if news { News::Check } else { News::None }
    }

    fn apply_record(
        &mut self,
        now: Instant,
        r: &v2::Record<'_>,
        packet: &PacketCerts<'_>,
        budget: &mut Admission,
    ) {
        let a = &r.alive.alive;
        let name = a.node.as_str();
        match r.state {
            RecordState::Alive => self.on_signed_alive(now, &r.alive, packet, budget, true),
            RecordState::Left { .. } => {
                if let Some(left) = r.left_message() {
                    self.on_signed_dead(now, &left, packet);
                }
            }
            RecordState::Suspect { inc } | RecordState::Dead { inc } => {
                let msg = v2::Message::Alive(r.alive);
                if self
                    .check(&msg, name, r.alive.certificate_id, packet)
                    .is_some()
                {
                    self.on_merged_suspicion(now, name, inc, a.epoch);
                }
            }
        }
    }

    /// Merges a version 2 push-pull frame's records, spending at most the checks this input
    /// has left; the rest wait for the next inputs.
    pub(crate) fn merge_v2(
        &mut self,
        now: Instant,
        records: v2::Records<'_>,
        packet: &PacketCerts<'_>,
        budget: &mut Admission,
    ) {
        let mut rest = records.iter();
        while let Some(r) = rest.next() {
            match self.record_news(&r, budget) {
                News::None => {}
                News::Refused => self.metrics.members_refused += 1,
                News::Check if self.checks_left() == 0 => {
                    let records = std::iter::once(r).chain(rest);
                    self.defer(records, packet, *budget);
                    return;
                }
                News::Check => self.apply_record(now, &r, packet, budget),
            }
        }
    }

    fn checks_left(&self) -> usize {
        self.keys.as_ref().map_or(0, |k| k.checks_left)
    }

    /// Copies what is left of a frame for later inputs, up to `max_members` records waiting
    /// in all.
    fn defer<'a>(
        &mut self,
        records: impl Iterator<Item = v2::Record<'a>>,
        packet: &PacketCerts<'_>,
        budget: Admission,
    ) {
        let max = self.cfg.max_members;
        let Some(keys) = self.keys.as_mut() else {
            return;
        };
        let room = max.saturating_sub(keys.deferred_len);
        let records: VecDeque<PendingRecord> =
            records.take(room).map(|r| PendingRecord::new(&r)).collect();
        if records.is_empty() {
            return;
        }
        keys.deferred_len += records.len();
        let certs = packet.iter().map(|(_, c)| c.encode()).collect();
        keys.deferred.push_back(Deferred {
            records,
            certs,
            budget,
        });
    }

    /// Handles deferred push-pull records with the checks this input has.
    pub(crate) fn drain_deferred(&mut self) {
        let now = self.now;
        loop {
            if self.checks_left() == 0 {
                return;
            }
            let Some(frame) = self.keys.as_mut().and_then(|k| k.deferred.pop_front()) else {
                return;
            };
            let Deferred {
                mut records,
                certs: cert_bytes,
                mut budget,
            } = frame;
            {
                let certs = packet_certs(
                    cert_bytes
                        .iter()
                        .filter_map(|bytes| Certificate::decode(bytes).ok()),
                );
                while let Some(pending) = records.pop_front() {
                    let r = pending.record();
                    match self.record_news(&r, &budget) {
                        News::None => {}
                        News::Refused => self.metrics.members_refused += 1,
                        News::Check if self.checks_left() == 0 => {
                            records.push_front(pending);
                            break;
                        }
                        News::Check => self.apply_record(now, &r, &certs, &mut budget),
                    }
                    if let Some(keys) = self.keys.as_mut() {
                        keys.deferred_len -= 1;
                    }
                }
            }
            if !records.is_empty() {
                if let Some(keys) = self.keys.as_mut() {
                    keys.deferred.push_front(Deferred {
                        records,
                        certs: cert_bytes,
                        budget,
                    });
                }
                return;
            }
        }
    }

    /// Whether deferred push-pull records wait for an input.
    pub(crate) fn has_deferred(&self) -> bool {
        self.keys.as_ref().is_some_and(|k| !k.deferred.is_empty())
    }

    /// What an Alive about `a.node` would do, without doing it: the same precedence as
    /// [`Node::on_alive`]. A signed copy of the unsigned Alive this node holds is news too,
    /// since it carries the proof this node lacks.
    pub(crate) fn alive_news(&self, a: &Alive<'_>, budget: &Admission) -> News {
        let name = a.node.as_str();
        let check = |b: bool| if b { News::Check } else { News::None };
        if name == self.local.member.name {
            let me = &self.local.member;
            return check(
                a.addr != me.addr
                    || match life(a.epoch, me.epoch) {
                        Life::Later => true,
                        Life::Same => newer(a.inc, me.incarnation),
                        Life::Earlier => false,
                    },
            );
        }
        let Some(entry) = self.table.get(name) else {
            return if budget.is_spent() || !self.has_room() {
                News::Refused
            } else {
                News::Check
            };
        };
        let old = &entry.member;
        match life(a.epoch, old.epoch) {
            Life::Earlier => News::None,
            Life::Same if !newer(a.inc, old.incarnation) => check(
                a.inc == old.incarnation
                    && a.addr == old.addr
                    && ((old.epoch == 0 && a.epoch != 0 && old.state.is_live())
                        || (entry.proof.is_none() && entry.holds(a))),
            ),
            Life::Same | Life::Later => News::Check,
        }
    }

    /// Whether a Suspect would change this node's view, by the precedence of
    /// [`Node::on_suspect`]. One about this node always acts, unless it left.
    pub(crate) fn suspect_news(&self, s: &Suspect<'_>) -> bool {
        let name = s.node.as_str();
        if name == self.local.member.name {
            return !self.has_left();
        }
        let Some(e) = self.table.get(name) else {
            return false;
        };
        if life(s.epoch, e.member.epoch) != Life::Same {
            return false;
        }
        let inc = e.member.incarnation;
        match e.member.state {
            crate::State::Alive => at_least(s.inc, inc),
            crate::State::Suspect if newer(s.inc, inc) => true,
            crate::State::Suspect if s.inc == inc => self
                .suspicions
                .get(name)
                .is_some_and(|sus| !sus.has_reporter(s.from.as_str())),
            _ => false,
        }
    }

    /// Whether a Dead would change this node's view, by the precedence of [`Node::on_dead`].
    pub(crate) fn dead_news(&self, d: &Dead<'_>) -> bool {
        let name = d.node.as_str();
        if name == self.local.member.name {
            return !self.has_left();
        }
        self.table.get(name).is_some_and(|e| {
            e.member.state.is_live()
                && life(d.epoch, e.member.epoch) == Life::Same
                && at_least(d.inc, e.member.incarnation)
        })
    }

    /// Whether a peer's Suspect or Dead record would start a merged suspicion, by the
    /// precedence of [`Node::on_merged_suspicion`].
    fn merged_news(&self, name: &str, inc: u32, epoch: u64) -> bool {
        if name == self.local.member.name {
            return !self.has_left();
        }
        self.table.get(name).is_some_and(|e| {
            life(epoch, e.member.epoch) == Life::Same
                && match e.member.state {
                    crate::State::Alive => at_least(inc, e.member.incarnation),
                    crate::State::Suspect => newer(inc, e.member.incarnation),
                    _ => false,
                }
        })
    }

    /// Live members held without a checked signature of their current Alive, or whose
    /// certificate is no longer valid.
    pub(crate) fn count_unsigned(&self) -> u64 {
        let Some(keys) = self.keys.as_ref() else {
            return 0;
        };
        let now = keys.unix_now(self.now);
        let unsigned = self.table.iter().filter(|e| {
            e.member.state.is_live()
                && !e.proof.is_some_and(|p| {
                    keys.certs
                        .get(&e.member.name)
                        .is_some_and(|c| c.id == p.cert && c.is_current(now))
                })
        });
        unsigned.count() as u64
    }

    /// Forgets the certificates of members whose tombstones were reaped.
    pub(crate) fn forget_reaped_certs(&mut self) {
        let Some(keys) = self.keys.as_mut() else {
            return;
        };
        let table = &self.table;
        keys.certs.retain(|name, _| table.get(name).is_some());
    }
}

/// What mode `sign` needs of a node beyond what [`Config::validate`](crate::Config::validate)
/// checks: an epoch, the clock its certificate is checked against; a certificate that names it
/// and is valid at that clock; and an address a signed Alive can carry.
pub(crate) fn signing_keys(
    credentials: &Credentials,
    cfg: &crate::Config,
    me: &crate::Identity,
    now: Instant,
) -> Result<Keys, crate::ConfigError> {
    let fail = |field, reason| Err(crate::ConfigError { field, reason });
    if me.epoch() == 0 {
        return fail("epoch", "must be set for a node that signs");
    }
    if let SocketAddr::V6(a) = me.addr() {
        if a.scope_id() != 0 || a.flowinfo() != 0 {
            return fail("addr", "must have no IPv6 scope or flow label to be signed");
        }
    }
    let Ok(cert) = Certificate::decode(&credentials.certificate) else {
        return fail("certificate", "is not a certificate");
    };
    if cert.name().as_str() != me.name() {
        return fail("certificate", "must name this node");
    }
    let keys = Keys::new(HeldCert::new(&cert), now, me.epoch());
    let label = cfg.cluster.as_bytes();
    let anchors = &credentials.trust_anchors;
    match cert.verify(anchors, label, keys.unix_now(now), CERTIFICATE_SKEW_SECS) {
        Ok(()) => Ok(keys),
        Err(_) => fail("certificate", "must be valid at this node's clock"),
    }
}

impl Node {
    /// Sends this node's signed Alive, behind its certificate, to the member `name` once this
    /// node learns that it speaks version 2: when it is new, starts a new life, or advertises
    /// version 2 where it did not. A member that heard of this node first in a version 1
    /// packet, a static member list or a 0.4 relay holds it unsigned until then.
    pub(crate) fn announce_to(&mut self, name: &str) {
        if self.keys.is_none() || self.has_left() {
            return;
        }
        let Some(to) = self.table.get(name).map(|e| e.member.addr) else {
            return;
        };
        if self.version_for(Some(name), to) != kinship_proto::WireVersion::V2 {
            return;
        }
        let gossip = self.local_alive_announced();
        let Some((cert, alive)) = gossip.signed() else {
            return;
        };
        let mut msgs: Vec<v2::Message<'_>> =
            cert.map(v2::Message::Certificate).into_iter().collect();
        msgs.push(alive);
        self.out.send_signed(to, &msgs);
    }
}
