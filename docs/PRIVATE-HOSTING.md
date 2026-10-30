# Private hosting through Tailscale Serve

The panel stays on this Windows PC. Tailscale Serve provides HTTPS to devices
permitted by the tailnet access policy. The PC, backend and Tailscale must remain
running. This is private hosting, not public internet hosting.

After building frontend/ with npm ci and npm run build, run from the repo root:

```powershell
$env:HONEYPOT_URL = 'https://YOUR-AUTHORIZED-LAB-HOST'
$env:TEST_TARGET_URL = $env:HONEYPOT_URL
$env:HONEYPOT_ALLOWED_HOSTS = 'YOUR-AUTHORIZED-LAB-HOST'
$node = tailscale status --json | ConvertFrom-Json
$env:PANEL_TAILSCALE_HOST = $node.Self.DNSName.TrimEnd('.')
$env:PANEL_ORIGINS = "http://localhost:5000,http://127.0.0.1:5000,https://$env:PANEL_TAILSCALE_HOST"
python -m uvicorn main:app --host 127.0.0.1 --port 5000 --no-proxy-headers
```

In another terminal:

```powershell
tailscale serve --bg --yes http://127.0.0.1:5000
tailscale serve status
```

Open the HTTPS URL while connected to Tailscale. Collaborators need tailnet
membership or device sharing and permission to reach this device; GitHub access
does not grant network access. No collaborators are invited automatically.

Keep Uvicorn loopback-only with --no-proxy-headers. The configured Tailscale
hostname requires Serve HTTPS and user identity headers. Origins remain checked
for HTTP and WebSocket requests. Local processes are trusted. Do not expose
the backend port or enable public Tailscale Funnel.

Remote users can run the fixed tests and read output. VPN changes are blocked
through the Tailscale hostname; manage them through the local panel.

To stop private hosting: tailscale serve --https=443 off
