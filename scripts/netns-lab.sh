#!/bin/sh
# Isolated end-to-end lab: runs lanscan against a routed topology inside
# unprivileged user + network namespaces. It sends no traffic on the host LAN.
#
#   ./scripts/netns-lab.sh            # builds, then runs every scenario
#
# Scenarios: passive (no probes, and no packets on the wire), echo/TCP
# validation on both backends with an on-wire Paris flow check, split DNS,
# routing epochs by polling and by rtnetlink notification, the 100-prefix
# acceptance estate (plus an 80 ms / 2% loss variant when netem is available),
# a journal on a full filesystem, a broken output pipe, and --listen (heard
# evidence, --no-ipv6, silence on the wire, and failure without CAP_NET_RAW).
#
# Topology (all inside private namespaces):
#   vantage 10.10.0.1 -- r1 (10.10.0.2 | 10.20.0.1 | 10.40.0.1)
#                          |-- r2 10.20.0.2, target 10.30.0.9 (echo)
#                          |-- r3 10.40.0.5 (drops echo; TCP 8443 listens)
#   vantage 10.50.0.1 -- est 10.50.0.2, hosts 10.100.N.10 for N in 0..99
#   vantage 10.60.0.1 -- lan 10.60.0.2 (+10.61.0.7), which broadcasts ARP,
#                         LLDP, RIP and an IPv6 router advertisement
set -eu
command -v tcpdump > /dev/null || { echo "netns-lab: tcpdump is required for the wire checks" >&2; exit 1; }
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

# Acceptance estate: 100 /24 prefixes behind router "est", one responsive
# host each (10.100.N.10), known from an inventory; the vantage has only an
# aggregate route, as with a VPN.
node est
link h1 e0 "$est"
ip link set h1 up
ip addr add 10.50.0.1/24 dev h1
at "$est" ip link set lo up
at "$est" ip link set e0 up
at "$est" ip addr add 10.50.0.2/24 dev e0
at "$est" ip route add default via 10.50.0.1
echo "realm,prefix,kind,source,observed_at" > "$work/estate.csv"
: > "$work/estate-seeds.txt"
n=0
while [ $n -lt 100 ]; do
	at "$est" ip addr add "10.100.$n.10/32" dev lo
	echo "lab,10.100.$n.0/24,subnet,ipam," >> "$work/estate.csv"
	echo "10.100.$n.10" >> "$work/estate-seeds.txt"
	n=$((n + 1))
done
ip route add 10.100.0.0/16 via 10.50.0.2

# A shared segment for --listen. IPv6 is off on the vantage side so its
# kernel sends nothing (no DAD or MLD) that could mask lanscan's silence.
node lan
link h2 l2 "$lan"
echo 1 > /proc/sys/net/ipv6/conf/h2/disable_ipv6
ip link set h2 up
ip addr add 10.60.0.1/24 dev h2
at "$lan" ip link set lo up
at "$lan" ip link set l2 up
at "$lan" ip addr add 10.60.0.2/24 dev l2
at "$lan" ip addr add 10.61.0.7/24 dev l2
at "$lan" python3 -c '
import socket, struct, time
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); s.bind(("l2", 0))
mac = s.getsockname()[4]
def eth(dst, etype, body): return dst + mac + struct.pack(">H", etype) + body
def csum(b):
    t = sum(struct.unpack(">%dH" % (len(b) // 2), b)); t = (t >> 16) + (t & 0xffff); return ~(t + (t >> 16)) & 0xffff
bcast = b"\xff" * 6
ip4 = socket.inet_aton
# Gratuitous ARP from a host in a subnet the vantage has no address in.
arp = eth(bcast, 0x0806, struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1) + mac + ip4("10.61.0.7") + b"\0" * 6 + ip4("10.61.0.7"))
def tlv(t, v): return struct.pack(">H", t << 9 | len(v)) + v
lldp = eth(bytes.fromhex("0180c200000e"), 0x88cc, tlv(1, b"\x04" + mac) + tlv(2, b"\x05l2") + tlv(3, b"\x00\x78") + tlv(5, b"lab-switch") + tlv(8, b"\x05\x01" + ip4("10.60.0.2") + b"\x02\0\0\0\x01\0") + tlv(0, b""))
rip = struct.pack(">BBH", 2, 2, 0) + struct.pack(">HH", 2, 0) + ip4("10.62.0.0") + ip4("255.255.0.0") + ip4("0.0.0.0") + struct.pack(">I", 1)
udp = struct.pack(">HHHH", 520, 520, 8 + len(rip), 0) + rip
hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 1, 17, 0, ip4("10.60.0.2"), ip4("255.255.255.255"))
hdr = hdr[:10] + struct.pack(">H", csum(hdr)) + hdr[12:]
riptx = eth(bcast, 0x0800, hdr + udp)
pio = struct.pack(">BBBBIII", 3, 4, 64, 0xc0, 3600, 1800, 0) + socket.inet_pton(socket.AF_INET6, "fd00:60::")
ra = struct.pack(">BBHBBHII", 134, 0, 0, 64, 0, 1800, 0, 0) + pio
ip6 = struct.pack(">IHBB", 6 << 28, len(ra), 58, 255) + socket.inet_pton(socket.AF_INET6, "fe80::2") + socket.inet_pton(socket.AF_INET6, "ff02::1")
ratx = eth(bytes.fromhex("333300000001"), 0x86dd, ip6 + ra)
while True:
    for f in (arp, lldp, riptx, ratx): s.send(f)
    time.sleep(0.3)
' & pids="$pids $!"
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
    expect(all(t["details"].get("flow_stable") is True for t in traces), "trace lost flow stability")
    expect(all(e["details"].get("flow") == "paris_constant_id_checksum" for e in hops), "hop without a Paris flow")
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
elif scenario in ("epoch", "epoch-notify"):
    epochs = [e for e in events if e["type"] == "routing_epoch"]
    expect(len(epochs) >= 1, "route removal did not start a routing epoch")
    expect(not probe("10.40.0.5", "connected"), "probed via a removed route")
    watch = [e for e in events if e["type"] == "capability" and e.get("source") == "topology_watch"]
    expect(watch and watch[0]["details"]["detection"] == "notification_and_polling", "rtnetlink notifications unavailable")
    if scenario == "epoch-notify":
        expect(epochs and epochs[0]["details"]["detection"] == "notification", "epoch not detected by notification: %r" % [e["details"].get("detection") for e in epochs])
elif scenario in ("listen", "listen-noipv6"):
    heard = [e for e in obs if e.get("source") == "listen"]
    def saw(proto, **kv):
        return any(e.get("protocol") == proto and all(e.get(k) == v for k, v in kv.items()) for e in heard)
    expect(saw("arp", address="10.61.0.7", interface_id="h2"), "gratuitous ARP from the foreign subnet")
    expect(any(e.get("protocol") == "lldp" and e.get("address") == "10.60.0.2" and e["details"].get("system_name") == "lab-switch" for e in heard), "LLDP neighbour")
    expect(saw("rip", prefix="10.62.0.0/16", prefix_basis="rip"), "RIP prefix")
    expect(any(e["type"] == "finding_upsert" and e.get("prefix") == "10.62.0.0/16" for e in events), "RIP prefix finding")
    ra = saw("ndp", prefix="fd00:60::/64", prefix_basis="router_advertisement")
    if scenario == "listen":
        expect(ra, "router advertisement prefix")
    else:
        expect(not any(":" in (e.get("address") or "") + (e.get("prefix") or "") for e in heard), "IPv6 evidence with --no-ipv6")
    status = [e for e in events if e["type"] == "collector_status" and e.get("source") == "listen"]
    expect(status and status[0]["outcome"] == "complete", "listen status %r" % status)
    expect(not any(e["type"] == "operation_reserved" for e in events), "listen reserved operations")
elif scenario == "passive":
    expect(not any(e["type"] == "operation_reserved" for e in events), "passive run reserved operations")
elif scenario in ("estate", "estate-wan"):
    responders = {e["address"] for e in obs if e.get("source") == "probe" and e.get("reachability") == "endpoint_response"}
    wanted = {"10.100.%d.10" % n for n in range(100)}
    missing = sorted(wanted - responders)
    elapsed = finished[0]["details"]["elapsed_ms"] / 1000 if finished else 0
    cov = finished[0]["details"]["coverage"] if finished else {}
    print("  %s: %d/100 prefixes detected in %.1fs, %d operations, responding prefixes %s" % (scenario, len(wanted & responders), elapsed, ops, cov.get("prefixes_with_responding_target")))
    expect(elapsed <= 120, "estate exceeded the 120-second profile: %.1fs" % elapsed)
    if scenario == "estate":
        expect(not missing, "undetected seeds %r" % missing)
    else:
        # Loss can defeat both echo and the TCP fallback; each miss must be
        # explained by silence (timeouts), never by a skipped target.
        silent = {e["address"] for e in obs if e.get("source") == "probe" and e.get("outcome") == "timeout"}
        expect(len(missing) <= 5, "too many undetected seeds under WAN loss: %r" % missing)
        expect(set(missing) <= silent, "undetected seeds were never probed: %r" % sorted(set(missing) - silent))
if fail:
    print("FAIL", scenario, "\n  " + "\n  ".join(fail)); sys.exit(1)
print("PASS", scenario, "operations=%d" % ops)
PY
}

# paris asserts that hop-limited echo requests (TTL below 16) to the trace
# target share one identifier and checksum on the wire.
paris() {
	python3 - "$1" <<'PY'
import struct, sys
data = open(sys.argv[1], "rb").read()
if len(data) < 24:
    print("FAIL paris: empty capture"); sys.exit(1)
link = struct.unpack("<I", data[20:24])[0]
off, flows, probes = 24, set(), 0
while off + 16 <= len(data):
    incl = struct.unpack("<I", data[off + 8:off + 12])[0]
    pkt = data[off + 16:off + 16 + incl]
    off += 16 + incl
    ip = pkt[14:] if link == 1 else pkt
    if len(ip) < 28 or ip[0] >> 4 != 4 or ip[9] != 1:
        continue
    ihl = (ip[0] & 15) * 4
    icmp = ip[ihl:]
    if ip[16:20] == bytes([10, 30, 0, 9]) and ip[8] < 16 and icmp[0] == 8:
        probes += 1
        flows.add(icmp[2:6])
if probes < 2 or len(flows) != 1:
    print("FAIL paris: %d trace probes on %d flows" % (probes, len(flows))); sys.exit(1)
print("PASS paris: %d trace probes on one flow" % probes)
PY
}

run() {
	name=$1; shift
	"$bin" --format jsonl --realm lab --vantage ns0 "$@" > "$work/$name.jsonl" 2> "$work/$name.err" || true
}

run passive --seeds "$work/seeds.txt"
check "$work/passive.jsonl" passive

# Ping sockets start disabled here, so the raw backend runs first; only gid 0
# is mapped, so the range cannot be disabled again once enabled.
for backend in raw ping; do
	if [ $backend = ping ]; then echo "0 0" > /proc/sys/net/ipv4/ping_group_range; fi
	# Capture on the vantage link so the trace's flow identifiers are checked on the wire.
	tcpdump --immediate-mode -Z root -U -n -i h0 -w - icmp > "$work/trace-$backend.pcap" 2>"$work/tcpdump-$backend.err" & cap=$!
	sleep 0.5
	run "validate-$backend" --intensity 1 --include 10.0.0.0/8 --seeds "$work/seeds.txt" --tcp-port 8443 --trace 1 --max-operations 20 --dns-budget 0 --rate 50 --timeout 500ms
	sleep 0.3; kill -INT $cap; wait $cap 2>/dev/null || true
	grep -o '"backend":"[a-z_0-9]*"' "$work/validate-$backend.jsonl" | sort -u | tr '\n' ' '; echo
	check "$work/validate-$backend.jsonl" validate
	paris "$work/trace-$backend.pcap"
done

printf 'app.corp.example\nother.test\n' > "$work/names.txt"
run dns --intensity 1 --include 10.30.0.0/24 --seeds "$work/names.txt" --resolver 10.20.0.2 --dns-suffix corp.example --dns-budget 4 --max-operations 20 --rate 50 --timeout 500ms
check "$work/dns.jsonl" dns

# Remove the r3 route mid-run: a new epoch must begin and stale work must skip.
( sleep 1.2; ip route del 10.40.0.0/24 ) &
run epoch --intensity 1 --include 10.0.0.0/8 --seeds "$work/seeds.txt" --sample-per-prefix 3 --tcp-port 8443 --rate 1 --max-operations 20 --dns-budget 0 --refresh-interval 500ms --timeout 300ms
check "$work/epoch.jsonl" epoch

# The same change with a one-minute poll: only rtnetlink can detect it in time.
ip route add 10.40.0.0/24 via 10.10.0.2
( sleep 1.2; ip route del 10.40.0.0/24 ) &
run epoch-notify --intensity 1 --include 10.0.0.0/8 --seeds "$work/seeds.txt" --sample-per-prefix 3 --tcp-port 8443 --rate 1 --max-operations 20 --dns-budget 0 --refresh-interval 60s --timeout 300ms
check "$work/epoch-notify.jsonl" epoch-notify

# Wire check: a passive run sends nothing (IPv4 or ARP) from the vantage.
tcpdump --immediate-mode -Z root -U -n -i any -w - "arp or (ip and not dst host 127.0.0.1)" > "$work/passive.pcap" 2>/dev/null & cap=$!
sleep 0.5
run passive-wire --seeds "$work/estate-seeds.txt" --inventory "$work/estate.csv"
sleep 0.3
# Positive control: the capture must see this ping, or zero proves nothing.
ping -c 1 -W 1 10.50.0.2 > /dev/null
sleep 0.3; kill -INT $cap; wait $cap 2>/dev/null || true
# Only outbound frames count; the control ping and any ARP it triggers involve its host.
packets=$(tcpdump -Z root -n -r "$work/passive.pcap" "outbound and not host 10.50.0.2" 2>/dev/null | grep -c "^[0-9][0-9]:" || true)
control=$(tcpdump -Z root -n -r "$work/passive.pcap" "icmp and dst host 10.50.0.2" 2>/dev/null | grep -c "^[0-9][0-9]:" || true)
if [ "$control" -lt 1 ]; then echo "FAIL passive-wire: capture missed the control ping"; exit 1; fi
if [ "$packets" -ne 0 ]; then echo "FAIL passive-wire: $packets packets"; tcpdump -Z root -n -r "$work/passive.pcap" | head; exit 1; fi
echo "PASS passive-wire: no packets besides the control ping"

# --listen records what the segment broadcasts and sends nothing itself.
h2mac=$(ip -o link show h2 | sed -n 's/.*link\/ether \([0-9a-f:]*\).*/\1/p')
tcpdump --immediate-mode -Z root -U -n -e -i h2 -w - > "$work/listen.pcap" 2>/dev/null & cap=$!
sleep 0.5
run listen --listen 2s --interface h2
sleep 0.3; kill -INT $cap; wait $cap 2>/dev/null || true
check "$work/listen.jsonl" listen
sent=$(tcpdump -Z root -n -r "$work/listen.pcap" "ether src $h2mac" 2>/dev/null | grep -c "^[0-9][0-9]:" || true)
heard=$(tcpdump -Z root -n -r "$work/listen.pcap" "not ether src $h2mac" 2>/dev/null | grep -c "^[0-9][0-9]:" || true)
if [ "$heard" -lt 4 ]; then echo "FAIL listen-wire: capture heard only $heard frames"; exit 1; fi
if [ "$sent" -ne 0 ]; then echo "FAIL listen-wire: vantage sent $sent frames"; tcpdump -Z root -n -e -r "$work/listen.pcap" "ether src $h2mac" | head; exit 1; fi
echo "PASS listen-wire: $heard frames heard, none sent"
run listen-noipv6 --listen 2s --interface h2 --no-ipv6
check "$work/listen-noipv6.jsonl" listen-noipv6

# Without CAP_NET_RAW over this network namespace (a nested user namespace
# does not own it), --listen must fail loudly and create no journal.
set +e
unshare -Ur "$bin" --listen 1s --journal "$work/nocap.jsonl" > /dev/null 2> "$work/nocap.err"
code=$?
set -e
if [ $code -eq 1 ] && grep -q CAP_NET_RAW "$work/nocap.err" && [ ! -e "$work/nocap.jsonl" ]; then
	echo "PASS listen-nocap exit=1: $(cat "$work/nocap.err")"
else
	echo "FAIL listen-nocap exit=$code: $(cat "$work/nocap.err")"; exit 1
fi

# Acceptance: 100 known prefixes, one responsive seed each, intensity 1.
tcpdump --immediate-mode -Z root -U -n -i h1 -w - "ip or arp" > "$work/estate.pcap" 2>/dev/null & cap=$!
sleep 0.5
run estate --intensity 1 --include 10.100.0.0/16 --seeds "$work/estate-seeds.txt" --inventory "$work/estate.csv"
sleep 0.3; kill -INT $cap; wait $cap 2>/dev/null || true
check "$work/estate.jsonl" estate
sent=$(tcpdump -Z root -n -r "$work/estate.pcap" src host 10.50.0.1 2>/dev/null | wc -l)
echo "  estate wire: $sent packets sent by the vantage (application operations are not packets)"

# The same estate over a lossy, high-latency link, when netem is available.
if tc qdisc add dev h1 root netem delay 80ms loss 2% 2>/dev/null && at "$est" tc qdisc add dev e0 root netem delay 80ms loss 2% 2>/dev/null; then
	run estate-wan --intensity 1 --include 10.100.0.0/16 --seeds "$work/estate-seeds.txt" --inventory "$work/estate.csv"
	check "$work/estate-wan.jsonl" estate-wan
	tc qdisc del dev h1 root; at "$est" tc qdisc del dev e0 root
else
	echo "SKIP estate-wan (netem unavailable)"
fi

# Fault injection: the journal fills a 64 KiB filesystem mid-run. The run must
# fail promptly and loudly, and every complete record must stay readable.
mkdir -p "$work/full"
set +e
unshare -m sh -c 'mount -t tmpfs -o size=64k tmpfs "$1" || exit 99; "$2" --journal "$1/j.jsonl" --realm lab --seeds "$3" --inventory "$4" --format jsonl; c=$?; cp "$1/j.jsonl" "$5"; exit $c' sh "$work/full" "$bin" "$work/estate-seeds.txt" "$work/estate.csv" "$work/full.jsonl" > "$work/full.out" 2> "$work/full.err"
code=$?
"$bin" export --journal "$work/full.jsonl" --format jsonl > "$work/full-export.jsonl" 2> "$work/full-export.err"
exported=$?
set -e
streamed=$(grep -c . "$work/full.out"); recovered=$(grep -c . "$work/full-export.jsonl")
if [ $code -ne 1 ] || ! grep -q "no space left on device" "$work/full.err"; then echo "FAIL disk-full: exit $code"; cat "$work/full.err"; exit 1; fi
# Export reports the incomplete run (exit 3); every streamed record must have
# been journaled first, so none is missing from the recovered journal.
if [ $exported -ne 3 ] || [ "$recovered" -lt "$streamed" ]; then echo "FAIL disk-full recovery: export exit $exported, $recovered recovered < $streamed streamed"; cat "$work/full-export.err"; exit 1; fi
echo "PASS disk-full exit=$code, $recovered complete records recovered, $streamed streamed"

# Broken pipe: the reader goes away after one record; the run must stop
# promptly with an error rather than continue writing into the void.
set +e
start=$(date +%s)
( "$bin" --realm lab --seeds "$work/estate-seeds.txt" --inventory "$work/estate.csv" --format jsonl 2> "$work/pipe.err"; echo $? > "$work/pipe.code" ) | head -n 1 > /dev/null
set -e
code=$(cat "$work/pipe.code"); took=$(( $(date +%s) - start ))
if [ "$code" -eq 0 ] || [ $took -gt 10 ]; then echo "FAIL broken-pipe: exit $code after ${took}s"; cat "$work/pipe.err"; exit 1; fi
echo "PASS broken-pipe exit=$code"
