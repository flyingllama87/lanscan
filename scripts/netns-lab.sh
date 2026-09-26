#!/bin/sh
# Isolated end-to-end lab: runs lanscan against a routed topology inside
# unprivileged user + network namespaces. It sends no traffic on the host LAN.
#
#   ./scripts/netns-lab.sh            # builds, then runs every scenario
#
# Topology (all inside private namespaces):
#   vantage 10.10.0.1 -- r1 (10.10.0.2 | 10.20.0.1 | 10.40.0.1)
#                          |-- r2 10.20.0.2, target 10.30.0.9 (echo)
#                          |-- r3 10.40.0.5 (drops echo; TCP 8443 listens)
set -eu
if [ "${LANSCAN_LAB_INNER:-}" != 1 ]; then
	root=$(cd "$(dirname "$0")/.." && pwd)
	work=$(mktemp -d)
	[ -n "${LANSCAN_KEEP:-}" ] && echo "work: $work" || trap 'rm -rf "$work"' EXIT
	(cd "$root" && go build -o "$work/lanscan" ./cmd/lanscan)
	LANSCAN_LAB_INNER=1 LANSCAN_BIN="$work/lanscan" LANSCAN_WORK="$work" exec unshare -rn sh "$0"
fi

bin=$LANSCAN_BIN
work=$LANSCAN_WORK
pids=""
cleanup() { for p in $pids; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

node() { unshare -n sleep 600 & pids="$pids $!"; eval "$1=$!"; }
at() { pid=$1; shift; nsenter -t "$pid" -n "$@"; }
link() { ip link add "$1" type veth peer name "$2"; ip link set "$2" netns "$3"; }

ip link set lo up
node r1; node r2; node r3
link h0 r1a "$r1"
ip link set h0 up
ip addr add 10.10.0.1/24 dev h0
at "$r1" ip link set lo up
at "$r1" ip link set r1a up
at "$r1" ip addr add 10.10.0.2/24 dev r1a
at "$r1" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'

at "$r1" ip link add r1b type veth peer name r2a
at "$r1" ip link set r2a netns "$r2"
at "$r1" ip link set r1b up
at "$r1" ip addr add 10.20.0.1/24 dev r1b
at "$r2" ip link set lo up
at "$r2" ip link set r2a up
at "$r2" ip addr add 10.20.0.2/24 dev r2a
at "$r2" ip addr add 10.30.0.9/32 dev lo
at "$r2" ip route add default via 10.20.0.1
at "$r1" ip route add 10.30.0.0/24 via 10.20.0.2

at "$r1" ip link add r1c type veth peer name r3a
at "$r1" ip link set r3a netns "$r3"
at "$r1" ip link set r1c up
at "$r1" ip addr add 10.40.0.1/24 dev r1c
at "$r3" ip link set lo up
at "$r3" ip link set r3a up
at "$r3" ip addr add 10.40.0.5/24 dev r3a
at "$r3" ip route add default via 10.40.0.1
at "$r3" sh -c 'echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all'
at "$r3" python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.40.0.5", 8443)); s.listen(16)
while True: s.accept()[0].close()
' & pids="$pids $!"

# Minimal authoritative responder for the lab zone (A and PTR only).
at "$r2" python3 -c '
import socket, struct
zone = {("app.corp.example", 1): socket.inet_aton("10.30.0.9"),
        ("9.0.30.10.in-addr.arpa", 12): b"".join(bytes([len(l)]) + l.encode() for l in "app.corp.example".split(".")) + b"\0"}
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.20.0.2", 53))
while True:
    q, peer = s.recvfrom(512)
    i, labels = 12, []
    while q[i]: labels.append(q[i+1:i+1+q[i]].decode().lower()); i += 1 + q[i]
    qtype = struct.unpack(">H", q[i+1:i+3])[0]; question = q[12:i+5]
    data = zone.get((".".join(labels), qtype))
    rcode = 0 if data or any(n == ".".join(labels) for n, _ in zone) else 3
    head = q[:2] + struct.pack(">HHHHH", 0x8400 | rcode, 1, 1 if data else 0, 0, 0)
    answer = struct.pack(">HHHIH", 0xC00C, qtype, 1, 60, len(data)) + data if data else b""
    s.sendto(head + question + answer, peer)
' & pids="$pids $!"

ip route add 10.20.0.0/16 via 10.10.0.2
ip route add 10.30.0.0/24 via 10.10.0.2
ip route add 10.40.0.0/24 via 10.10.0.2
sleep 0.3

printf '10.30.0.9\n10.40.0.5\n' > "$work/seeds.txt"

check() {
	python3 - "$@" <<'PY'
import json, sys
path, scenario = sys.argv[1], sys.argv[2]
events = [json.loads(l) for l in open(path)]
obs = [e for e in events if e["type"] == "observation"]
def probe(addr, outcome):
    return any(e.get("source") == "probe" and e.get("address") == addr and e.get("outcome") == outcome for e in obs)
fail = []
def expect(cond, msg):
    if not cond: fail.append(msg)
finished = [e for e in events if e["type"] == "run_finished"]
expect(len(finished) == 1, "run_finished missing")
ops = finished[0]["details"]["operations"] if finished else 0
if scenario == "validate":
    expect(probe("10.30.0.9", "echo_reply"), "echo to routed target")
    expect(probe("10.40.0.5", "timeout"), "echo dropped by r3 should be unknown/timeout")
    expect(probe("10.40.0.5", "connected"), "TCP fallback to r3:8443")
    hops = [e for e in obs if e.get("source") == "trace"]
    hop_addrs = [e.get("address") for e in hops]
    expect(hop_addrs == ["10.10.0.2", "10.30.0.9"], "trace hops %r" % hop_addrs)
    expect(hops and hops[0]["outcome"] == "time_exceeded" and hops[0]["reachability"] == "unknown", "hop 1 must be a transit response")
    expect(all(e.get("prefix") is None for e in hops), "trace invented a prefix")
    traces = [e for e in events if e["type"] == "trace_finished"]
    expect(any(t["outcome"] == "destination_reached" for t in traces), "trace summary")
    expect(ops <= 20, "budget exceeded: %d" % ops)
    findings = [e for e in events if e["type"] == "finding_upsert" and e.get("address") == "10.30.0.9" and e.get("prefix")]
    expect(all(f["prefix"] == "10.30.0.0/24" and f["prefix_basis"] == "route" for f in findings), "response associated with non-evidenced prefix")
elif scenario == "dns":
    fwd = [e for e in obs if e.get("source") == "dns_forward" and e.get("address")]
    expect({e["address"] for e in fwd} == {"10.30.0.9"}, "forward answers %r" % [e.get("address") for e in fwd])
    expect(any(e["details"].get("derived_from_ptr") == "10.30.0.9" for e in fwd), "PTR name was not forward-confirmed")
    expect(all(e["details"]["resolver_policy"] == "explicit" for e in fwd), "resolver policy not recorded")
    expect(not any(e.get("source") == "dns_forward" and e.get("name") == "other.test" for e in obs), "queried a name outside the approved suffix")
    expect(probe("10.30.0.9", "echo_reply"), "DNS answer was not validated")
    ptr = [e for e in obs if e.get("source") == "dns_reverse" and e.get("name")]
    expect([e["name"] for e in ptr] == ["app.corp.example"], "PTR naming evidence %r" % [e.get("name") for e in ptr])
    expect(all(e.get("reachability") == "unknown" for e in fwd + ptr), "DNS promoted to reachability")
    dns_ops = finished[0]["details"]["coverage"]["operations_by_method"].get("dns", 0) if finished else 0
    expect(dns_ops <= 4, "DNS budget exceeded: %d" % dns_ops)
elif scenario == "epoch":
    epochs = [e for e in events if e["type"] == "routing_epoch"]
    expect(len(epochs) >= 1, "route removal did not start a routing epoch")
    expect(not probe("10.40.0.5", "connected"), "probed via a removed route")
elif scenario == "passive":
    expect(not any(e["type"] == "operation_reserved" for e in events), "passive run reserved operations")
if fail:
    print("FAIL", scenario, "\n  " + "\n  ".join(fail)); sys.exit(1)
print("PASS", scenario, "operations=%d" % ops)
PY
}

run() {
	name=$1; shift
	"$bin" discover --no-journal --format jsonl --realm lab --vantage ns0 "$@" > "$work/$name.jsonl" 2> "$work/$name.err" || true
}

run passive --seeds "$work/seeds.txt"
check "$work/passive.jsonl" passive

# Ping sockets start disabled here, so the raw backend runs first; only gid 0
# is mapped, so the range cannot be disabled again once enabled.
for backend in raw ping; do
	if [ $backend = ping ]; then echo "0 0" > /proc/sys/net/ipv4/ping_group_range; fi
	run "validate-$backend" --active --include 10.0.0.0/8 --seeds "$work/seeds.txt" --tcp-port 8443 --trace 1 --max-operations 20 --dns-budget 0 --rate 50 --timeout 500ms
	grep -o '"backend":"[a-z_0-9]*"' "$work/validate-$backend.jsonl" | sort -u | tr '\n' ' '; echo
	check "$work/validate-$backend.jsonl" validate
done

printf 'app.corp.example\nother.test\n' > "$work/names.txt"
run dns --active --include 10.30.0.0/24 --seeds "$work/names.txt" --resolver 10.20.0.2 --dns-suffix corp.example --dns-budget 4 --max-operations 20 --rate 50 --timeout 500ms
check "$work/dns.jsonl" dns

# Remove the r3 route mid-run: a new epoch must begin and stale work must skip.
( sleep 1.2; ip route del 10.40.0.0/24 ) &
run epoch --active --include 10.0.0.0/8 --seeds "$work/seeds.txt" --sample-per-prefix 3 --tcp-port 8443 --rate 1 --max-operations 20 --dns-budget 0 --refresh-interval 500ms --timeout 300ms
check "$work/epoch.jsonl" epoch
