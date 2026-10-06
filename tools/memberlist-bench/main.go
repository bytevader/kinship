// Command memberlist-node runs one hashicorp/memberlist node, with DefaultLANConfig, under
// kinship's chaos harness (tools/chaos), which measures its detection latency against
// kinship's.
//
// It speaks the harness's line protocol, the same as tools/chaos's chaos-node: one JSON object
// per line on stdout, "ready" with its pid once it has joined, then "alive", "dead" and "left"
// for member events (memberlist reports no suspicions), and "stats" when asked. It reads the
// commands "stats" and "quit" from stdin and exits when stdin closes.
//
//	memberlist-node -name n0 -bind 10.77.0.1:7946 -key BASE64
//	memberlist-node -name n1 -bind 10.77.0.2:7946 -key BASE64 -seed 10.77.0.1:7946
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/memberlist"
)

var out sync.Mutex

// emit writes one line; the harness times each event when the line arrives.
func emit(v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out.Lock()
	defer out.Unlock()
	os.Stdout.Write(append(b, '\n'))
}

type events struct{ self string }

func (e *events) report(ev string, n *memberlist.Node) {
	if n.Name != e.self {
		emit(map[string]any{"ev": ev, "member": n.Name})
	}
}

func (e *events) NotifyJoin(n *memberlist.Node) { e.report("alive", n) }

func (e *events) NotifyLeave(n *memberlist.Node) {
	if n.State == memberlist.StateLeft {
		e.report("left", n)
	} else {
		e.report("dead", n)
	}
}

func (e *events) NotifyUpdate(*memberlist.Node) {}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "memberlist-node:", err)
		emit(map[string]any{"ev": "error", "error": err.Error()})
		os.Exit(1)
	}
}

func run() error {
	name := flag.String("name", "", "node name")
	bind := flag.String("bind", "", "UDP and TCP listen address, host:port")
	key := flag.String("key", "", "cluster key, 32 bytes in base64; plaintext without one")
	seed := flag.String("seed", "", "seed to join, host:port")
	flag.Parse()
	if *name == "" || *bind == "" {
		return fmt.Errorf("-name and -bind are required")
	}
	host, portText, err := net.SplitHostPort(*bind)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}

	cfg := memberlist.DefaultLANConfig()
	cfg.Name = *name
	cfg.BindAddr, cfg.BindPort = host, port
	cfg.AdvertiseAddr, cfg.AdvertisePort = host, port
	cfg.Events = &events{self: *name}
	cfg.LogOutput = os.Stderr
	if *key != "" {
		if cfg.SecretKey, err = base64.StdEncoding.DecodeString(*key); err != nil {
			return fmt.Errorf("bad key: %w", err)
		}
	}
	m, err := memberlist.Create(cfg)
	if err != nil {
		return err
	}
	if *seed != "" {
		// Like kinship's startup join: a few attempts with backoff, then give up.
		wait := cfg.ProbeInterval
		for attempt := 1; ; attempt++ {
			if _, err = m.Join([]string{*seed}); err == nil {
				break
			}
			if attempt == 5 {
				return fmt.Errorf("join %s: %w", *seed, err)
			}
			time.Sleep(wait)
			wait *= 2
		}
	}
	emit(map[string]any{"ev": "ready", "pid": os.Getpid(), "name": *name, "addr": *bind})

	stdin := bufio.NewScanner(os.Stdin)
	for stdin.Scan() {
		switch cmd := strings.TrimSpace(stdin.Text()); cmd {
		case "stats":
			emit(map[string]any{
				"ev":           "stats",
				"local_health": m.GetHealthScore(),
				"members":      m.NumMembers(),
			})
		case "quit":
			return m.Shutdown()
		case "":
		default:
			emit(map[string]any{"ev": "error", "error": "unknown command " + cmd})
		}
	}
	// The harness closed the pipe or died: do not linger in its namespace.
	return m.Shutdown()
}
