//! The test network and the faults injected into it.
//!
//! Every node gets its own network namespace, `kchaos-<i>`, with one veth `eth0` at
//! `10.77.x.y/16`. The other ends of the veths sit on a bridge in a hub namespace, `kchaos-hub`,
//! so nothing touches the host's own namespace and its firewall. Faults go on each node's
//! `eth0`: tc netem for loss, delay, jitter and reordering on everything the node sends, and an
//! nftables table that drops the node's UDP in one direction.
//!
//! Only this module runs commands as root, through [`Root`].

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// The port every node binds, UDP and TCP.
pub const PORT: u16 = 7946;

const HUB: &str = "kchaos-hub";

/// The most nodes [`addr`] can number.
pub const MAX_NODES: usize = 250 * 250;

/// Node `i`'s namespace.
pub fn ns(i: usize) -> String {
    format!("kchaos-{i}")
}

/// Node `i`'s address.
pub fn addr(i: usize) -> SocketAddr {
    assert!(i < MAX_NODES, "node {i} is beyond the address plan");
    let ip = Ipv4Addr::new(10, 77, (i / 250) as u8, (i % 250 + 1) as u8);
    (ip, PORT).into()
}

/// How root commands are run: `sudo -n`, nothing when the harness already runs as root, or the
/// command in `CHAOS_SUDO`, split on whitespace.
///
/// Only the network setup, the fault injection and the start of each node (`ip netns exec`)
/// go through it; the node itself drops back to the harness's user with setpriv.
#[derive(Debug, Clone)]
pub struct Root {
    prefix: Vec<String>,
    /// `--reuid`, `--regid` for setpriv when the harness is not root itself.
    user: Option<(String, String)>,
}

impl Root {
    pub async fn detect() -> Result<Self, String> {
        let uid = output("id", &["-u"]).await?;
        let gid = output("id", &["-g"]).await?;
        let user = (uid != "0").then_some((uid, gid));
        let prefix = match std::env::var("CHAOS_SUDO") {
            Ok(p) => p.split_whitespace().map(str::to_owned).collect(),
            Err(_) if user.is_none() => Vec::new(),
            Err(_) => vec!["sudo".to_owned(), "-n".to_owned()],
        };
        Ok(Self { prefix, user })
    }

    /// `program` with `args`, run as root.
    fn command<S: AsRef<str>>(&self, program: &str, args: &[S]) -> Command {
        let mut all: Vec<&str> = self.prefix.iter().map(String::as_str).collect();
        all.push(program);
        all.extend(args.iter().map(AsRef::as_ref));
        let mut cmd = Command::new(all[0]);
        cmd.args(&all[1..]).kill_on_drop(true);
        cmd
    }

    /// A command that runs `program` inside node `i`'s namespace as the harness's user.
    pub fn in_node(&self, i: usize, program: &str, args: &[String]) -> Command {
        let mut all = vec!["netns".to_owned(), "exec".to_owned(), ns(i)];
        if let Some((uid, gid)) = &self.user {
            let setpriv = [
                "setpriv",
                "--reuid",
                uid,
                "--regid",
                gid,
                "--init-groups",
                "--",
            ];
            all.extend(setpriv.map(str::to_owned));
        }
        all.push(program.to_owned());
        all.extend_from_slice(args);
        self.command("ip", &all)
    }

    /// Runs `script` with `sh -e` as root and fails with its output if it fails or takes
    /// longer than `limit`.
    pub async fn script(&self, script: &str, limit: Duration) -> Result<(), String> {
        let mut child = self
            .command("sh", &["-es"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot run {:?}: {e}", self.prefix))?;
        let mut stdin = child.stdin.take().expect("stdin is piped");
        stdin
            .write_all(script.as_bytes())
            .await
            .map_err(|e| format!("cannot write the script: {e}"))?;
        drop(stdin);
        let out = tokio::time::timeout(limit, child.wait_with_output())
            .await
            .map_err(|_| format!("a root script took longer than {limit:?}:\n{script}"))?
            .map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "a root script failed ({}):\n{}{}\nscript:\n{script}",
                out.status,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            ))
        }
    }
}

async fn output(program: &str, args: &[&str]) -> Result<String, String> {
    let out = tokio::time::timeout(
        Duration::from_secs(10),
        Command::new(program).args(args).output(),
    )
    .await
    .map_err(|_| format!("{program} did not finish"))?
    .map_err(|e| format!("cannot run {program}: {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// tc netem settings, applied to everything a node sends.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Netem {
    pub delay_ms: f64,
    pub jitter_ms: f64,
    pub loss_pct: f64,
    /// Share of packets sent at once instead of after the delay, so they overtake others.
    pub reorder_pct: f64,
}

impl Netem {
    pub fn is_none(&self) -> bool {
        *self == Self::default()
    }

    /// The arguments after `tc qdisc ... netem`.
    pub fn tc_args(&self) -> String {
        let mut args = String::new();
        if self.delay_ms > 0.0 {
            args += &format!(" delay {}ms", self.delay_ms);
            if self.jitter_ms > 0.0 {
                args += &format!(" {}ms", self.jitter_ms);
            }
        }
        if self.loss_pct > 0.0 {
            args += &format!(" loss {}%", self.loss_pct);
        }
        // netem reorders only delayed traffic.
        if self.reorder_pct > 0.0 && self.delay_ms > 0.0 {
            args += &format!(" reorder {}%", self.reorder_pct);
        }
        args.trim_start().to_owned()
    }

    /// Parses the [`Display`](fmt::Display) form, `delay=5ms,jitter=2ms,loss=3%,reorder=10%`,
    /// any subset in any order, or `none`.
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut n = Self::default();
        if text == "none" {
            return Ok(n);
        }
        for part in text.split(',').filter(|p| !p.is_empty()) {
            let (key, value) = part
                .split_once('=')
                .ok_or(format!("netem: expected key=value, got {part}"))?;
            let number = |suffix: &str| {
                value
                    .strip_suffix(suffix)
                    .unwrap_or(value)
                    .parse::<f64>()
                    .ok()
                    .filter(|v| v.is_finite() && *v >= 0.0)
                    .ok_or(format!("netem: bad {key} {value}"))
            };
            match key {
                "delay" => n.delay_ms = number("ms")?,
                "jitter" => n.jitter_ms = number("ms")?,
                "loss" => n.loss_pct = number("%")?,
                "reorder" => n.reorder_pct = number("%")?,
                _ => return Err(format!("netem: unknown setting {key}")),
            }
        }
        Ok(n)
    }
}

impl fmt::Display for Netem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_none() {
            return f.write_str("none");
        }
        write!(
            f,
            "delay={}ms,jitter={}ms,loss={}%,reorder={}%",
            self.delay_ms, self.jitter_ms, self.loss_pct, self.reorder_pct
        )
    }
}

/// Which of a node's UDP an nftables rule drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Datagrams to the node: it never sees a Ping, an Ack or gossip over UDP.
    Inbound,
    /// Datagrams from the node: its Acks, Pings and gossip never leave.
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        })
    }
}

/// The namespaces of one harness run. [`Net::destroy`] removes them; [`Net::create`] first
/// removes any a crashed run left behind.
#[derive(Debug)]
pub struct Net {
    pub root: Root,
    pub nodes: usize,
    /// The ARP table limits to restore, when this run raised them.
    arp: Option<[u64; 3]>,
}

impl Net {
    pub async fn create(root: Root, nodes: usize) -> Result<Self, String> {
        if nodes == 0 || nodes > MAX_NODES {
            return Err(format!("--nodes must be 1 to {MAX_NODES}"));
        }
        cleanup(&root).await?;
        let mut s = format!(
            "ip netns add {HUB}\n\
             ip -n {HUB} link set lo up\n\
             ip -n {HUB} link add br0 type bridge\n\
             ip -n {HUB} link set br0 up\n"
        );
        for i in 0..nodes {
            let ns = ns(i);
            let ip = addr(i).ip().to_string();
            s += &format!(
                "ip netns add {ns}\n\
                 ip -n {ns} link add eth0 type veth peer name v{i} netns {HUB}\n\
                 ip -n {HUB} link set v{i} master br0 up\n\
                 ip -n {ns} addr add {ip}/16 dev eth0\n\
                 ip -n {ns} link set eth0 up\n\
                 ip -n {ns} link set lo up\n"
            );
        }
        let limit = Duration::from_secs(60) + Duration::from_millis(200) * nodes as u32;
        // The ARP table is shared by every namespace, and its default ceiling of 1,024 entries
        // overflows at about 32 nodes that all talk to each other.
        let arp = read_arp_limits()?;
        let need = arp_limits(nodes);
        let raised = (arp[2] < need[2]).then_some(arp);
        if raised.is_some() {
            s += &set_arp_limits(need);
            eprintln!("chaos: raising the ARP table limits from {arp:?} to {need:?} for this run");
        }
        let net = Self {
            root,
            nodes,
            arp: raised,
        };
        if let Err(e) = net.root.script(&s, limit).await {
            let _ = net.destroy().await;
            return Err(e);
        }
        Ok(net)
    }

    /// Removes the namespaces and puts back the ARP table limits.
    pub async fn destroy(&self) -> Result<(), String> {
        cleanup(&self.root).await?;
        match self.arp {
            Some(old) => {
                self.root
                    .script(&set_arp_limits(old), Duration::from_secs(30))
                    .await
            }
            None => Ok(()),
        }
    }

    /// Sets netem on every node, replacing what was there; `Netem::default()` removes it.
    pub async fn netem_all(&self, netem: &Netem) -> Result<(), String> {
        let mut s = String::new();
        for i in 0..self.nodes {
            let ns = ns(i);
            if netem.is_none() {
                s += &format!("tc -n {ns} qdisc del dev eth0 root 2>/dev/null || true\n");
            } else {
                s += &format!(
                    "tc -n {ns} qdisc replace dev eth0 root netem {}\n",
                    netem.tc_args()
                );
            }
        }
        self.root.script(&s, self.limit()).await
    }

    /// Drops node `i`'s UDP on the protocol port in one direction.
    pub async fn block_udp(&self, i: usize, dir: Direction) -> Result<(), String> {
        let (hook, port) = match dir {
            Direction::Inbound => ("input", "dport"),
            Direction::Outbound => ("output", "sport"),
        };
        let s = format!(
            "ip netns exec {ns} nft -f - <<'EOF'\n\
             table inet kchaos {{\n\
             \tchain udp_block {{\n\
             \t\ttype filter hook {hook} priority 0; policy accept;\n\
             \t\tudp {port} {PORT} drop\n\
             \t}}\n\
             }}\n\
             EOF\n",
            ns = ns(i)
        );
        self.root.script(&s, Duration::from_secs(30)).await
    }

    pub async fn unblock_udp(&self, i: usize) -> Result<(), String> {
        let s = format!(
            "ip netns exec {} nft delete table inet kchaos 2>/dev/null || true\n",
            ns(i)
        );
        self.root.script(&s, Duration::from_secs(30)).await
    }

    fn limit(&self) -> Duration {
        Duration::from_secs(30) + Duration::from_millis(100) * self.nodes as u32
    }
}

const GC_THRESH: [&str; 3] = [
    "net.ipv4.neigh.default.gc_thresh1",
    "net.ipv4.neigh.default.gc_thresh2",
    "net.ipv4.neigh.default.gc_thresh3",
];

fn read_arp_limits() -> Result<[u64; 3], String> {
    let mut v = [0; 3];
    for (slot, key) in v.iter_mut().zip(GC_THRESH) {
        let path = format!("/proc/sys/{}", key.replace('.', "/"));
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("cannot read {path}: {e}"))?;
        *slot = text
            .trim()
            .parse()
            .map_err(|_| format!("bad value in {path}"))?;
    }
    Ok(v)
}

/// Room for every node to hold an entry for every other, twice over before the kernel starts
/// collecting, and twice that before it refuses.
fn arp_limits(nodes: usize) -> [u64; 3] {
    let all = (nodes * nodes) as u64;
    [all, 2 * all, 4 * all].map(|v| v.max(1024))
}

fn set_arp_limits(v: [u64; 3]) -> String {
    GC_THRESH
        .iter()
        .zip(v)
        .map(|(key, value)| format!("sysctl -qw {key}={value}\n"))
        .collect()
}

/// Removes every namespace a harness run created, and nothing else.
pub async fn cleanup(root: &Root) -> Result<(), String> {
    let s = "for ns in $(ip netns list | awk '{print $1}' | grep -E '^kchaos-(hub|[0-9]+)$'); do\n\
             \tip netns delete \"$ns\"\n\
             done\n";
    root.script(s, Duration::from_secs(120)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_distinct_and_never_end_in_zero() {
        let all: std::collections::HashSet<_> = (0..1000).map(addr).collect();
        assert_eq!(all.len(), 1000);
        assert_eq!(addr(0).to_string(), "10.77.0.1:7946");
        assert_eq!(addr(249).to_string(), "10.77.0.250:7946");
        assert_eq!(addr(250).to_string(), "10.77.1.1:7946");
    }

    #[test]
    fn netem_round_trips_through_its_display_form() {
        let n = Netem::parse("delay=5ms,jitter=2.5ms,loss=3%,reorder=10%").unwrap();
        assert_eq!(
            n,
            Netem {
                delay_ms: 5.0,
                jitter_ms: 2.5,
                loss_pct: 3.0,
                reorder_pct: 10.0
            }
        );
        assert_eq!(Netem::parse(&n.to_string()).unwrap(), n);
        assert_eq!(n.tc_args(), "delay 5ms 2.5ms loss 3% reorder 10%");
        assert_eq!(Netem::parse("none").unwrap(), Netem::default());
        assert_eq!(Netem::default().to_string(), "none");
        assert!(Netem::parse("loss=-1%").is_err());
        assert!(Netem::parse("rate=1mbit").is_err());
    }

    #[test]
    fn arp_limits_leave_room_for_every_pair() {
        assert_eq!(arp_limits(5), [1024, 1024, 1024]);
        assert_eq!(arp_limits(100), [10_000, 20_000, 40_000]);
        assert_eq!(
            set_arp_limits([1, 2, 3]),
            "sysctl -qw net.ipv4.neigh.default.gc_thresh1=1\n\
             sysctl -qw net.ipv4.neigh.default.gc_thresh2=2\n\
             sysctl -qw net.ipv4.neigh.default.gc_thresh3=3\n"
        );
    }

    #[test]
    fn netem_reorders_only_with_a_delay() {
        let n = Netem {
            loss_pct: 2.0,
            reorder_pct: 5.0,
            ..Netem::default()
        };
        assert_eq!(n.tc_args(), "loss 2%");
    }
}
