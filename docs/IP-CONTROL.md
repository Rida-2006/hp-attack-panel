# IP control

Rotate IP reconnects the installed Windows WireGuard tunnel (default service
`WireGuardTunnel$wg2`; configurable using `WIREGUARD_SERVICE_NAME`). It does not
provision a proxy pool or choose a new VPN exit. A fixed exit can retain its IP.

The browser asks before changing this PC's IPv4 route. The backend reserves the
same execution slot used by attacks, obtains a baseline IPv4 using HTTPS ipify,
reconnects the fixed tunnel and checks the resulting address. It reports a change
only when the observed addresses differ. Missing baseline connectivity prevents
changes. Failed connectivity triggers an attempt to stop the tunnel and restore
direct routing. If an initially stopped tunnel produces no observed IP change,
it is stopped again. Recovery failures are shown explicitly. Backend interruption
can prevent recovery; deactivate wg2 using WireGuard or Turn VPN off if necessary.

The service being running does not prove a healthy handshake or routing. An IP
change does not prove anonymity, IPv6 coverage or DNS routing. The existing VPN
toolbar is a manual service control; its Turn VPN on button does not run the
Rotate IP verification procedure.

Verification: mocked service/IP tests cover actual change, unchanged address,
missing baseline, lost connectivity, authentication header and execution lock.
Browser tests mock `/api/vpn/rotate`; they do not alter the real network. No real
VPN reconnection or new public IP is claimed from these tests.

Wi-Fi inspection on October 30 found the wireless adapter connected, wg2 stopped,
and a Wi-Fi default route. Windows logs also showed wireless reconnects and Intel
missed-beacon events. Those observations do not establish the cause of previous
interruptions. A full-tunnel VPN routing failure can interrupt internet access
without disabling the Wi-Fi adapter.
