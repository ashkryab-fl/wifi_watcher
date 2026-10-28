# WiFi Watcher

Graphical and terminal packet monitor for a test LAN, built for macOS. 
Python 3.10+ with Tk and Scapy are required; `run.sh` prepares.
the virtual environment. Traffic capture does not require router web credentials;
reading DHCP names does.

Double-click `WiFiWatcher.command` in Finder to open the graphical interface.
Keep this launcher in the project folder. The terminal launcher remains available
with `./run.sh`; no standalone binary is needed.

## Graphical interface

The main window contains search, date/time and domain filters, and the live domain/IP
list. **Налаштування…** opens a separate window with discovery, device selection,
connection/disconnection, network fields, the HTTPS certificate, and the demo.

1. Open **Налаштування…** and click **Знайти девайси**. The LAN interface and
   gateway are detected automatically. macOS authorizes a separate capture helper;
   the GUI remains unprivileged.
2. DHCP names are requested automatically after discovery, using `router.username`
   and `router.password` in `config.json`. The config stores credentials in plain
   text with owner-only permissions. A router error leaves discovered devices usable.
3. Select a device and click **Підключити**. HTTP/HTTPS inspection is always enabled;
   prepare and trust the CA first (see below). This Mac uses mitmproxy Local Capture;
   allow **Mitmproxy Redirector** in macOS settings on first use. Setup waits up to
   two minutes and remains cancellable. The helper revalidates IP/MAC before relay
   for a separate LAN device.
4. Select a domain/IP to open its request browser. The left pane has **one column**:
   URL, or domain/IP when HTTP is unavailable. URL rows are grouped by exact path,
   ignoring query strings for grouping. Groups start expanded, ordered by newest
   activity; requests within each group are newest first. Full URLs keep their query
   strings. Connections with only metadata appear as domain/IP leaves, not invented URLs.
5. The remaining space shows **Огляд**, **Запит**, and **Відповідь** tabs with time,
   method, status/error, headers and available bodies. Responses update the original
   request. Matching transport packets are suppressed from the request list once
   their decoded HTTP connection is available. Metadata-only connections show the
   available endpoints, protocol and totals. **Усі домени** returns to the main list.
6. Search is literal. Date bounds accept `YYYY-MM-DD` or `YYYY-MM-DD HH:MM:SS`,
   in Europe/Kyiv, with an inclusive upper bound. Blank bounds cover the current
   connection. Filters on the two pages are independent. **Лише з доменом** hides
   IP-only groups. Main list headings sort domain names, TX/RX totals or last activity.
7. Open settings and click **Від’єднати** to restore ARP and stop capture. Controls
   unlock after cleanup is acknowledged. Closing the app requests the same cleanup.

There is no saved GUI history or session selector. Capture data stays in memory,
remains readable after disconnect, and is discarded on the next connection or app
exit. Startup removes old `logs/traffic.sqlite3` files and regular JSONL logs without
following symlinks; the CA is retained. Capture recording and queries run outside
Tk's event loop. The domain list displays up to 1000 groups.

After an unexpected stop, the device selection/name remain available for reconnect.
The helper matches the selected MAC after refreshing discovery, including after a
DHCP IP change. Status and cleanup errors remain visible. **Демонстрація**, in
settings, supplies synthetic data without administrator access or network changes.

## HTTPS inspection

Install mitmproxy separately (`brew install --cask mitmproxy`). In settings, click
**Сертифікат HTTPS…**, install/trust the public CA on the test device, and connect.
There is no HTTPS checkbox. Leave the device's manual Wi-Fi proxy off. Open a
captured domain to inspect its requests/responses in the main window.

See [setup, limits, and cleanup](docs/https.md). This Mac uses a macOS network
extension to capture outgoing connections. Separate LAN devices use macOS
forwarding and a scoped pf anchor for external IPv4 HTTP/HTTPS over TCP;
IPv4 UDP port 443 is rejected for the selected device during the session so
browsers can fall back from QUIC/HTTP/3 to TCP. Restart the browser after
connecting. IPv6 still bypasses this LAN mode. Certificate pinning can prevent decoding.

## Disconnect and crash recovery

- The GUI sends a heartbeat to the helper. EOF or a heartbeat gap of about five
  seconds stops capture and restores the real ARP mappings.
- Relay also starts an independent privileged guardian **before** any ARP changes.
  If the capture process is killed, pipe EOF triggers recovery. If its event loop
  stalls for about ten seconds, the guardian terminates that process first, then
  sends the restoration frames. It holds a per-device/interface lock until recovery
  completes, preventing overlapping copies from poisoning the same device.
- A normal stop sends genuine mappings five times and disarms the guardian only
  after successful cleanup. Network/restore errors remain visible instead of
  reporting a successful recovery.
- Unicast ARP checks run every three seconds during relay, with broadcast retries
  after repeated missed replies. Valid relayed traffic from each peer within the
  last fifteen seconds also confirms that peer is reachable. A changed MAC stops
  capture immediately on detection; three consecutive checks without either ARP
  responses or recent traffic stop it. This prevents an abandoned relay from following an old
  device IP indefinitely. Capture storage failures close the GUI/helper connection
  and trigger the same recovery path.

These mechanisms cover process crashes and forced application closure while the
Mac and its network adapter are running. They cannot send packets during power
loss, sleep, Wi-Fi disconnection, or if the guardian is also killed. ARP protection
or hardware/driver behavior can also prevent peers from accepting restoration.
If connectivity does not return, reconnect the monitored device to Wi-Fi. Use
**Від’єднати** before sleeping/disconnecting the Mac. Live device recovery still
needs a real network test; automated crash tests use a recovery callback without
altering the current network.

## Terminal interface

Alternatively, run from Terminal:

```sh
./run.sh
```

Live discovery/capture requests `sudo` locally. Choose an interface if prompted,
then a device from the ARP response list, then `p` (passive) or `r` (IPv4 relay).
The list includes DHCP names, IP and MAC addresses, with labels for this computer
and router. To read names, enter the router web username and password at the local
prompt. The password is hidden, kept in memory for the request, and never saved
or logged. A blank username skips this step; `--no-router-names` disables the
prompt. Noninteractive runs skip router authentication.

DHCP lookup uses the TL-WR841N cookie authentication and read-only `ACT_GL`
`LAN_HOST_ENTRY` request from its web interface. Names are matched to ARP devices
by MAC, not IP. The selected name also appears in the dashboard and the JSONL
session record (`target_name`, `target_name_source`). DHCP-only entries are not
added as active devices. A failed login or unsupported firmware falls back to
IP/MAC without automatic login retries; router settings are not changed.

Sleeping devices, client isolation, and hosts that ignore ARP can limit discovery.
It is not an authoritative router association list.

For the current LAN:

```sh
./run.sh --interface en0 --gateway 192.168.0.1 --relay
```

The relay flag selects the capture method; the device is still selected from the
list. Only the selected device's gateway traffic is redirected. Use Ctrl+C to
stop; SIGTERM also triggers cleanup.

## What is displayed

- Recent packets: local timestamp, TX/RX relative to the selected device,
  protocol, source/destination IP and port, original captured frame length.
- Packet counts, TX/RX totals, trailing one-second rates, protocol counts.
- Remote endpoints ranked by total TX + RX frame bytes.
- Domain names, when visible in DNS responses, TLS ClientHello SNI, or HTTP Host.
- Terminal logs are off by default. Explicit `--log FILE` writes JSONL metadata,
  UTC timestamps and a summary, with no payloads or raw packet captures. Files use
  mode `0600`; existing paths are never overwritten. `--no-log` disables recording.

## Domain names

Names appear first, with the original IP retained for reference:

```text
www.example.com:443 [198.51.100.10:443]
www.example.com:443 [198.51.100.10:443 DNS?]
```

TLS SNI and HTTP Host names are associated with the individual TCP connection,
in both directions. Different connections to a shared CDN IP can have different
names. The initial TCP prefix is reassembled within a 64 KiB limit, tolerating
reordered segments and retransmissions. Connection state is bounded and expires
after an hour without packets; incomplete header buffers expire after 30 seconds.
Starting capture after the handshake may miss the name.

Plain UDP DNS responses supply TTL-limited candidate names. `DNS?` indicates a
possible mapping, not proof that a connection requested that site. Multiple names
for a shared IP are retained instead of selecting one arbitrarily. Encrypted DNS
(DoH/DoT), QUIC ClientHello, and fragmented DNS are not decoded. ECH can hide the
actual TLS name; a visible outer name is marked `ECH outer?`. Unknown names fall
back to IP addresses. Metadata tracking performs no reverse DNS requests or
TLS decryption. The graphical app additionally enables HTTPS inspection, including
Local Capture for this Mac.

JSONL packet records retain `source`/`destination` IPs and add
`source_domains`/`destination_domains` arrays and
`source_domain_source`/`destination_domain_source` evidence (`dns`, `tls_sni`,
`tls_sni_outer`, `http_host`, or `null`). Previously written records are not
rewritten when a name is learned later. Restart the program to use this feature.
Names describe observed connections/lookups, not a complete browser history: pages
load third-party resources and browsers can reuse connections across origins.
Ordinary metadata mode does not log URL paths, cookies, request bodies, or raw
packets. GUI HTTPS inspection holds bounded HTTP content in memory separately.

Bytes measure captured link-layer frame lengths, not application payload size,
Wi-Fi airtime, or billing usage. Retransmissions count again. Capture or relay
performance can cause losses. Metadata queue overflow is displayed and logged;
that counter does not measure kernel, network, or forwarding losses. Rates in
offline mode measure replay processing, not the original capture's throughput.

## Capture methods and limits

**Passive:** observes traffic already delivered to the interface. Ordinary
switched Ethernet/Wi-Fi usually does not deliver another client's unicast traffic
to this Mac. Passive mode is useful for this computer or a mirrored switch port;
an empty display does not establish that the device is idle.

**Terminal relay:** sends ARP replies so the selected IPv4 client and gateway temporarily
address their Ethernet frames to this Mac. The program forwards these frames
directly at layer 2, without changing IP packets, system routing, IP forwarding,
or VPN settings. Stop the program to send the genuine ARP mappings back to both
peers. This is an active network operation and can interrupt the selected device,
especially if the Mac sleeps, capture fails, or traffic exceeds Python's forwarding
capacity. Keep the Mac awake. Use this mode only on your test network.

Relay requires the Mac, client, and router on the same LAN, Ethernet-compatible
capture/injection, and a network that accepts the ARP updates. Client isolation,
ARP protection, or some Wi-Fi drivers/APs can prevent it from working. Connecting
the Mac to a LAN port is an alternative if Wi-Fi forwarding does not work. Relay
covers **IPv4 via the selected gateway only**: IPv6, direct traffic between LAN
peers, other VLANs, and alternate gateways can bypass it. No completeness is
claimed. Passive capture can report IPv6 when those frames are visible.

On Ctrl+C, SIGTERM, or a handled error, the program sends restoration replies five
times before closing capture. The independent guardian also covers a killed
capture process, subject to the limits above. If the device loses connectivity,
reconnect it to Wi-Fi to refresh its ARP state. If ARP
updates are blocked, capture on a capable router or mirrored switch port is needed.
The web administration login alone does not supply a packet capture stream.

## Other commands

```sh
./run.sh --list                         # Discover only
./run.sh --gui                          # Graphical interface
./run.sh --gui --demo                   # Graphical synthetic demo
./run.sh --passive --target 192.168.0.108
./run.sh --relay --duration 60          # Stop and restore after 60 seconds
./run.sh --demo --no-log                # Synthetic example; no sudo/network I/O
./run.sh --read capture.pcap --target 192.168.0.103 --plain
./run.sh --help
.venv/bin/python -m unittest discover -s tests -v
```

Offline capture reading supports PCAP/PCAPNG through Scapy and filters by the
specified IP; a device's other IPs are not inferred. Live discovery uses at most
1024 IPv4 addresses; override with `--subnet 192.168.0.0/24` when needed. VPN
interfaces are excluded from automatic LAN selection. TLS/QUIC content remains
encrypted; only visible domain metadata is inspected in addition to network and
transport headers.

References: [Wireshark capture visibility](https://wiki.wireshark.org/CaptureSetup/Ethernet),
[Scapy packet I/O](https://scapy.readthedocs.io/en/stable/usage.html),
[TLS SNI](https://www.rfc-editor.org/rfc/rfc6066.html),
[ECH](https://www.rfc-editor.org/rfc/rfc9849.html).
