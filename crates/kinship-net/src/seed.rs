//! Seeds given by DNS name, and their lookup.
//!
//! The core only ever sees addresses. A [`Seed::Host`] is looked up here, at every join and every
//! rejoin, and every address the name has, A and AAAA records alike, becomes a seed of that
//! attempt. A name with several records, such as a Kubernetes headless Service, is a whole seed
//! list, and one that moves to new addresses is followed.

use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, timeout};

/// The longest a single lookup may take, or a slow resolver could hold up a join or a rejoin.
pub(crate) const LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);

/// The first wait between lookups while no seed resolves; it doubles up to [`RETRY_MAX`].
const RETRY_MIN: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(5);

/// The longest DNS name, without its final dot.
const MAX_NAME: usize = 253;

/// A seed: an address, or a host name and port that is looked up at every join and rejoin.
///
/// Parse one from `"host:port"`, where the host is an IP address (IPv6 in brackets) or a DNS
/// name. Every address a name resolves to, IPv4 and IPv6, is a seed.
///
/// ```
/// use kinship_net::Seed;
///
/// let ip: Seed = "10.0.0.5:7946".parse().unwrap();
/// assert_eq!(ip, Seed::Addr("10.0.0.5:7946".parse().unwrap()));
/// let name: Seed = "kinship-0.kinship.default.svc:7946".parse().unwrap();
/// assert_eq!(name.to_string(), "kinship-0.kinship.default.svc:7946");
/// assert!("node-1".parse::<Seed>().is_err(), "the port is required");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Seed {
    /// An address, used as it is.
    Addr(SocketAddr),
    /// A DNS name and the port its members listen on.
    Host { name: String, port: u16 },
}

impl Seed {
    fn host(&self) -> Option<(&str, u16)> {
        match self {
            Self::Addr(_) => None,
            Self::Host { name, port } => Some((name, *port)),
        }
    }
}

impl From<SocketAddr> for Seed {
    fn from(addr: SocketAddr) -> Self {
        Self::Addr(addr)
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Addr(a) => a.fmt(f),
            Self::Host { name, port } => write!(f, "{name}:{port}"),
        }
    }
}

/// A seed that is not `host:port` with an IP address or a DNS name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedError {
    input: String,
}

impl fmt::Display for SeedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seed {:?} is not \"host:port\" with an IP address or a DNS name",
            self.input
        )
    }
}

impl std::error::Error for SeedError {}

impl FromStr for Seed {
    type Err = SeedError;

    fn from_str(s: &str) -> Result<Self, SeedError> {
        let s = s.trim();
        if let Ok(addr) = s.parse() {
            return Ok(Self::Addr(addr));
        }
        let bad = || SeedError {
            input: s.to_owned(),
        };
        let (name, port) = s.rsplit_once(':').ok_or_else(bad)?;
        let port = port.parse().map_err(|_| bad())?;
        let name = name.strip_suffix('.').unwrap_or(name);
        if !is_dns_name(name) {
            return Err(bad());
        }
        Ok(Self::Host {
            name: name.to_owned(),
            port,
        })
    }
}

/// Dot-separated labels of letters, digits, `-` and `_`, none empty, longer than 63 bytes or
/// starting or ending with `-`. Rules out IP literals that failed to parse, such as unbracketed
/// IPv6, along with anything a resolver would reject or misread.
fn is_dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// What one round of lookups found.
#[derive(Debug, Default)]
pub(crate) struct Resolved {
    /// Every address of every seed, in the order of the seeds and without repeats.
    pub addrs: Vec<SocketAddr>,
    /// Names that resolved to no address.
    pub failed: usize,
}

/// Looks up every name among `seeds` at once, each for at most `limit`, and logs each that
/// resolves to nothing: as a warning for a join, which someone waits on, and at debug level for
/// a background rejoin, which tries again every `rejoin_interval`.
pub(crate) async fn resolve(seeds: &[Seed], limit: Duration, background: bool) -> Resolved {
    let mut lookups = JoinSet::new();
    for (i, seed) in seeds.iter().enumerate() {
        if let Some((name, port)) = seed.host() {
            let name = name.to_owned();
            lookups.spawn(async move {
                let found =
                    match timeout(limit, tokio::net::lookup_host((name.as_str(), port))).await {
                        Ok(Ok(addrs)) => Ok(addrs.collect::<Vec<_>>()),
                        Ok(Err(e)) => Err(e.to_string()),
                        Err(_) => Err("lookup timed out".to_owned()),
                    };
                (i, found)
            });
        }
    }
    let mut found: Vec<Option<Vec<SocketAddr>>> = vec![None; seeds.len()];
    let mut out = Resolved::default();
    while let Some(done) = lookups.join_next().await {
        let Ok((i, r)) = done else {
            out.failed += 1;
            continue;
        };
        let error = match r {
            Ok(addrs) if !addrs.is_empty() => {
                found[i] = Some(addrs);
                continue;
            }
            Ok(_) => "no address".to_owned(),
            Err(e) => e,
        };
        out.failed += 1;
        let seed = &seeds[i];
        if background {
            tracing::debug!(%seed, %error, "seed did not resolve; trying again at the next rejoin");
        } else {
            tracing::warn!(%seed, %error, "seed did not resolve");
        }
    }
    for (seed, found) in seeds.iter().zip(found) {
        let addrs = match seed {
            Seed::Addr(a) => vec![*a],
            Seed::Host { .. } => found.unwrap_or_default(),
        };
        for a in addrs {
            if !out.addrs.contains(&a) {
                out.addrs.push(a);
            }
        }
    }
    if !out.addrs.is_empty() && seeds.iter().any(|s| s.host().is_some()) {
        tracing::debug!(addrs = ?out.addrs, "resolved seeds");
    }
    out
}

/// Resolves `seeds` for a join, looking up again with backoff while every name fails and no
/// seed is an address, for up to `wait`. `None` if nothing resolved by then.
pub(crate) async fn resolve_for_join(seeds: &[Seed], wait: Duration) -> Option<Vec<SocketAddr>> {
    let deadline = Instant::now() + wait;
    let mut delay = RETRY_MIN;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let r = resolve(seeds, LOOKUP_TIMEOUT.min(left.max(RETRY_MIN)), false).await;
        if !r.addrs.is_empty() || r.failed == 0 {
            return Some(r.addrs);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        tracing::info!(retry_in = ?delay.min(left), "no seed resolved; looking up again");
        sleep(delay.min(left)).await;
        delay = (delay * 2).min(RETRY_MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(name: &str, port: u16) -> Seed {
        Seed::Host {
            name: name.to_owned(),
            port,
        }
    }

    #[test]
    fn seeds_parse_as_addresses_or_dns_names() {
        let ok = |s: &str| s.parse::<Seed>().unwrap();
        assert_eq!(
            ok("10.0.0.5:7946"),
            Seed::Addr("10.0.0.5:7946".parse().unwrap())
        );
        assert_eq!(
            ok(" [::1]:7946 "),
            Seed::Addr("[::1]:7946".parse().unwrap())
        );
        assert_eq!(ok("node-1:7946"), host("node-1", 7946));
        assert_eq!(ok("localhost:0"), host("localhost", 0));
        assert_eq!(
            ok("kinship.default.svc.cluster.local.:7946"),
            host("kinship.default.svc.cluster.local", 7946)
        );
        assert_eq!(ok("_kinship.example:1"), host("_kinship.example", 1));
        for bad in [
            "",
            "node-1",
            "node-1:",
            ":7946",
            "node-1:70000",
            "node-1:-1",
            "::1:7946",
            "[::1]",
            "[node-1]:7946",
            "-node:7946",
            "node-:7946",
            "a..b:7946",
            "a b:7946",
            "node/1:7946",
        ] {
            assert!(bad.parse::<Seed>().is_err(), "{bad:?} parsed");
        }
        let long = format!("{}:1", "a".repeat(64));
        assert!(long.parse::<Seed>().is_err(), "a 64-byte label");
        let err = "node-1".parse::<Seed>().unwrap_err().to_string();
        assert!(err.contains("\"node-1\""), "{err}");
    }

    #[test]
    fn seeds_print_as_they_parse() {
        for s in ["10.0.0.5:7946", "[::1]:7946", "node-1:7946"] {
            assert_eq!(s.parse::<Seed>().unwrap().to_string(), s);
        }
    }

    #[tokio::test]
    async fn localhost_resolves_and_addresses_pass_through() {
        let addr: SocketAddr = "10.0.0.5:7946".parse().unwrap();
        let seeds = [Seed::Addr(addr), host("localhost", 7946), Seed::Addr(addr)];
        let r = resolve(&seeds, LOOKUP_TIMEOUT, false).await;
        assert_eq!(r.failed, 0);
        assert_eq!(r.addrs[0], addr, "in the order of the seeds");
        assert!(
            r.addrs[1..]
                .iter()
                .all(|a| a.ip().is_loopback() && a.port() == 7946)
        );
        assert!(r.addrs.len() >= 2, "{:?}", r.addrs);
        assert_eq!(
            r.addrs.iter().filter(|&&a| a == addr).count(),
            1,
            "without repeats"
        );
    }

    #[tokio::test]
    async fn an_unresolvable_name_fails_alone_and_a_join_gives_up_after_its_wait() {
        // .invalid never resolves (RFC 6761).
        let gone = host("kinship-seed.invalid", 7946);
        let addr: SocketAddr = "10.0.0.5:7946".parse().unwrap();
        let r = resolve(&[gone.clone(), Seed::Addr(addr)], LOOKUP_TIMEOUT, false).await;
        assert_eq!((r.addrs, r.failed), (vec![addr], 1));

        let wait = Duration::from_millis(600);
        let start = Instant::now();
        assert_eq!(
            resolve_for_join(std::slice::from_ref(&gone), wait).await,
            None
        );
        assert!(start.elapsed() >= wait, "{:?}", start.elapsed());
        // An address always resolves, so the join goes ahead at once.
        assert_eq!(
            resolve_for_join(&[gone, Seed::Addr(addr)], Duration::from_secs(60)).await,
            Some(vec![addr])
        );
        assert_eq!(resolve_for_join(&[], Duration::ZERO).await, Some(vec![]));
    }
}
