# HTTPS inspection

macOS graphical mode, with offline addon validation against mitmproxy 12.2.3.
The GUI always enables inspection: Local Capture for this Mac, transparent IPv4
relay for separate LAN devices. Terminal capture is metadata-only.

## Setup

1. Install mitmproxy if needed: `brew install --cask mitmproxy`. Restart the app.
2. Open **Налаштування…**, click **Знайти девайси**, then select the test device.
   DHCP device names are requested automatically.
3. Click **Сертифікат HTTPS…**. The app generates/reuses its CA in
   `logs/https-ca/`. Open the displayed LAN URL on the device in the same Wi-Fi
   network, or export the public certificate. Allow incoming connections in the
   macOS application firewall if needed. The HTTP download server serves only
   the public CA and an iOS profile, never the CA directory or private key.
4. iPhone/iPad: install the downloaded profile in Settings → General → VPN &
   Device Management, then enable full trust in General → About → Certificate
   Trust Settings. Android: install as a CA in security/credential settings.
   Modern Android apps must also opt into user CA trust, for example in a debug
   Network Security Configuration for an app you control. Pinning needs separate
   app-specific configuration.
   This Mac: import the public CA into Keychain Access and set it to **Always Trust**.
   Installing a CA alone does not redirect or decrypt traffic.
5. Leave the device's manual Wi-Fi proxy **off** and click **Підключити**. HTTPS
   is always enabled; there is no toggle. Missing mitmproxy/CA blocks the connection.
   For this Mac, allow **Mitmproxy Redirector** when macOS asks. In System Settings
   → General → Login Items & Extensions, enable its network extension (switch to
   By Category → Network Extensions if needed). The entry appears after the first
   connection attempt. Local setup waits up to two minutes, with **Від’єднати**
   available to cancel. Restart the browser or reopen the site after connecting;
   existing connections are not retroactively decrypted.
6. Open a domain/IP in the main list. The single-column tree groups URLs by path,
   with newest groups/requests first and query strings preserved on URL leaves.
   The right pane has overview, request and response tabs. Responses/errors update
   the original request. Failed TLS handshakes appear as domain/IP rows with error
   details and identify whether the failure was between the proxy and device or
   between the proxy and website, since no HTTP URL was observed.
7. Use **Від’єднати** before shutting down the Mac. No router settings or device
   proxy settings are changed. Abrupt power loss can still interrupt connectivity.

## Content and limits

If Chrome on the inspected Android device shows full HTTPS URLs but an app only
shows `TLS` errors, the browser capture path is working. A client disconnect
during the handshake does not identify the exact cause: check the app's CA trust,
certificate pinning, and device-side TLS error. For an app you control, configure
its debug HTTP client to trust this project's public CA. Android Network Security
Configuration applies to clients using Android's trust configuration; Dart
`dart:io` clients may need an explicit `SecurityContext` with the additional CA.
See [Android debug CAs](https://developer.android.com/privacy-and-security/security-config#debug-overrides)
and [Dart trusted certificate bytes](https://api.dart.dev/dart-io/SecurityContext/setTrustedCertificatesBytes.html).

- Separate LAN devices: external IPv4 TCP ports 80/443 only. External IPv4 UDP
  port 443 is rejected for the selected device during the session so browsers
  can fall back from QUIC/HTTP/3 to HTTP/2 or HTTP/1.1 over TCP. Restart the
  browser after connecting to discard existing QUIC sessions. Apps requiring
  QUIC without a TCP fallback will fail on this port. LAN destinations, IPv6,
  other ports, WebSocket messages, and additional application encryption are
  not decoded; IPv6 can still bypass inspection.
- This Mac: mitmproxy's macOS network extension captures outgoing TCP/UDP
  connections across applications; protocol decoding follows mitmproxy's support.
  It does not capture already established connections. Pinning and application
  trust restrictions still apply. Passive DNS/SNI alone can miss domains because
  of DNS caching, encrypted DNS, QUIC or ECH; decoded HTTP supplies observed hosts
  directly to the main domain list.
- Bodies over 64 KiB are streamed without saving the full body. Headers are
  capped at 32 KiB/100 entries per message. The viewer decodes UTF-8, JSON and
  bounded gzip/deflate/zstd, shows binary as HEX and other compression as Base64.
  HTTP Host/:authority supplies the domain in transparent mode, where the
  original destination may be an IP address.
- CA installation does not bypass certificate pinning or Android app trust
  policies. Test with a fresh connection after installing the CA.
- HTTP snapshots, headers and bodies stay in memory for the current connection.
  A new connection or app exit discards them. Old traffic databases/JSONL files
  are removed at GUI startup; the CA is retained so device trust remains valid.
  The viewer does not export full PCAPs or complete streams.
- Queue overflow reports dropped HTTP snapshots separately from packet metadata;
  neither counter measures total network/forwarding losses.

## Implementation contract

The GUI/in-memory storage and public certificate server remain unprivileged.
For this Mac, the helper launches `mitmdump --mode local` as the CA directory's
owner, so extension approval belongs to the GUI user's login session. This path
does not change ARP, pf, forwarding or system proxy settings. Startup is polled
while the helper continues servicing heartbeats/disconnect. Parent-pipe EOF is
watched before server setup, including while macOS approval is pending.

For separate LAN devices, the helper
launches privileged mitmdump for macOS original-destination lookup via pf state.
No sudoers edits or trust-store changes are made on the Mac. Only the selected
device's external TCP 80/443 connections are redirected to a loopback listener.

Unlike the ordinary L2 relay, the kernel forwards in HTTPS mode. Outgoing
connections follow macOS routing, including VPN routes. Scapy observes but does
not send duplicate IP frames. The guardian owns a unique anchor below the
existing system `com.apple/*` rdr/filter hooks, a pf enable reference, and temporary IPv4
forwarding/ICMP redirect settings. It also temporarily sets
`net.link.generic.system.hwcksum_rx=0`: macOS can otherwise reject correctly
checksummed Wi-Fi packets after pf redirection because hardware checksum
metadata is stale. Receive checksums are validated in software across the Mac
during the session; the guardian restores the previous setting on cleanup,
including setup failure or helper death. Missing rdr/filter hooks fail before ARP changes.
The main pf rules and unrelated states are never flushed. No persistent network
configuration files are edited. A host-wide lock prevents overlapping HTTPS
sessions from restoring each other's intermediate sysctl values.

Cleanup restores ARP before removing the anchor, restores original sysctl values
unless another process changed them, releases only its pf reference, then stops
mitmdump. The guardian also cleans up after helper failure; mitmdump exits on
parent-pipe EOF. Cleanup errors remain visible. Existing power/sleep/network-loss
limits still apply; automatic recovery during Mac power loss is not guaranteed.

ARP health probes exclude this Mac's own interception announcements before
Scapy matches replies and accept only replies addressed to this Mac. Genuine
peer MAC changes still stop capture, with the IP and expected/observed MACs
included in the error.

The CA is reused across restarts. Incomplete CA files are rejected, not silently
replaced. Keep `logs/https-ca/mitmproxy-ca.pem` private; distribute only
`mitmproxy-ca-cert.pem` or the dialog's public `.cer`/profile.

Automated validation covers offline CA generation, real mitmdump synthetic
HTTP/TLS hooks, storage, local startup/cancellation, forwarding selection, and
mocked pf setup/cleanup. Local extension approval and browser decryption,
real-device TLS decryption, kernel forwarding, and visual layout still require
live verification. Tests do not change routing, pf, ARP, or trust stores.

References: [mitmproxy transparent mode](https://docs.mitmproxy.org/stable/howto/transparent/),
[CA certificates](https://docs.mitmproxy.org/stable/concepts/certificates/).
