# SSRF Probe — Burp Suite Extension

> Alternative to **Collaborator Everywhere** that works with **Burp Community**.
> You define the callback endpoint — ngrok, webhook.site, oastify, or any other.

---

## Why this extension?

| Problem with Collaborator Everywhere | Solution in SSRF Probe |
|---|---|
| Requires Burp Suite **Pro** | ✅ Works with **Community** |
| Fixed endpoint (Burp Collaborator) | ✅ **You choose** the endpoint |
| Collaborator may be blocked by WAF | ✅ Use ngrok, webhook.site, your own server |
| No canary visibility | ✅ Full log with canary map |
| No header selection | ✅ Choose exactly which headers to inject |

---

## Installation

### 1. Configure Jython in Burp
Download `jython-standalone-2.7.x.jar` → https://www.jython.org/download
`Extender → Options → Python Environment → select the .jar`

### 2. Load the Extension
`Extensions → Add → Type: Python → select SSRFProbe.py`

No dependencies beyond Jython.

---

## How to use

### 1. Configure the Endpoint
In the **SSRF Probe → Configuration** tab, select the mode and enter the value:

| Mode | What to paste | Generated payload |
|---|---|---|
| **Burp Collaborator** | Your collaborator domain | `http://CANARY.domain.oastify.com` |
| **Custom DNS** | Your controlled domain | `http://CANARY.yourdomain.com` |
| **Custom HTTP** | Full URL of your server | `https://yourserver.com/CANARY` |
| **Interactsh** | Your interactsh subdomain | `http://CANARY.subdomain.oast.fun` |
| **Localhost / Internal SSRF** | IP from presets | Static URL (no canary) |
| **ngrok** | Your ngrok subdomain | `https://subdomain.ngrok.io/CANARY` |
| **Webhook.site DNS Hook** | Everything after `*.` e.g. `8f713526-...dnshook.site` | `http://CANARY.8f713526-...dnshook.site` |

### 2. Select headers and options
- Check/uncheck HTTP headers to inject
- Enable "Inject in Parameters" for SSRF-prone parameters (`url=`, `redirect=`, JSON bodies, etc.)
- Enable "Scope only" to limit to the pentest target

### 3. Enable Interception
Click **ENABLE INTERCEPTION** — the extension will automatically modify all Proxy and Repeater requests. (Scanner/Intruder traffic is deliberately left untouched.)

### 4. Monitor the Log
**Injection Log** tab: view all modified requests with URL, injection count, sample payload and canary token.

---

## How the Canary Works

For each injection, a unique **canary token** (8 alphanumeric chars) is generated.
The injected payload format:

```
http://CANARY.YOUR_ENDPOINT
```

Example with Webhook.site DNS Hook (`8f713526-7500-4513-8662-40f4f97d6e2d.dnshook.site`):
```
http://x7k2p9qr.8f713526-7500-4513-8662-40f4f97d6e2d.dnshook.site
```

- `x7k2p9qr.8f713526-...` → detects **DNS OOB** (out-of-band)
- When the target server makes a request, you see the hit on your endpoint

---

## Default Injected Headers (28)

```
X-Forwarded-For      X-Forwarded-Host     X-Host
X-Original-URL       X-Rewrite-URL        X-Real-IP
Client-IP            True-Client-IP       Cluster-Client-IP
X-ProxyUser-Ip       Via                  Forwarded
X-Originating-IP     X-Remote-IP          X-Remote-Addr
X-Client-IP          CF-Connecting-IP     Fastly-Client-Ip
X-Forwarded          X-Wap-Profile        Contact
Referer              Origin               X-Original-Host
X-Backend-Host       Destination          X-HTTP-Host-Override
X-Custom-IP-Authorization
```

You can deselect individually or add custom headers.

### Header payload style
Headers that semantically take a **hostname** (`Host`, `X-Forwarded-Host`, `X-Host`, `X-Original-Host`, `X-Backend-Host`, `X-HTTP-Host-Override`, `Via`) receive a hostname-only payload (e.g. `CANARY.oastify.com`); all other headers receive the full URL payload (e.g. `http://CANARY.oastify.com/x7k2p9qr`).

### ⚠️ About the Host header
`Host` is present in the list but is **NOT selected by default**: replacing the Host header breaks virtual-host routing to the target on every request. Only select it deliberately for specific tests.

---

## Auto-Detected Parameters

The extension detects parameters whose name suggests SSRF and rewrites their value with the payload:

`url, uri, path, src, source, dest, destination, redirect, return, next, target, link, href, action, goto, site, page, ref, referrer, callback, proxy, fetch, load, file, image, img, request, domain, host, endpoint, service, api, continue, forward, open, data, feed, webhook, notify, ping`

Supported parameter locations:
- **Query string** (rewritten in the request line)
- **Body** `application/x-www-form-urlencoded`
- **JSON bodies** (`{"url": "..."}` → `{"url": "http://CANARY..."}`)

---

## Context Menu (Right-Click)

Right-click any request → **SSRF Probe**:

### "Individual Scan (1 header per request)"
- Opens a **floating window** (like Turbo Intruder) — closeable with X
- Sends N separate requests, one per header
- Table: `# | Header | Status | Size | Time(ms) | Canary | Payload`
- Click any row to see the exact request sent and the full response
- Runs in background without freezing Burp

### "Inject All at Once (Repeater)"
- Injects all headers at once
- Opens directly in Repeater with the modified request

---

## Recommended Endpoints

| Service | Free | DNS OOB | HTTP OOB | Persistence |
|---|:---:|:---:|:---:|:---:|
| **Burp Collaborator** (oastify.com) | ⚠️ Pro only | ✅ | ✅ | Session |
| **Webhook.site** | ✅ | ✅ (dnshook) | ✅ | 7 days |
| **ngrok** | ✅ | ❌ | ✅ | Session |
| **Interactsh** (projectdiscovery) | ✅ | ✅ | ✅ | Session |
| **canarytokens.org** | ✅ | ✅ | ✅ | Permanent |
| **Your own server** | ✅ | ✅* | ✅ | Permanent |

\* Requires your own DNS server for DNS OOB

---

## Troubleshooting

### Extension loads but nothing is injected
- Check that **ENABLE INTERCEPTION** is active (green status)
- Make sure the endpoint is filled in and saved
- If "Scope only" is checked, add the target to Burp's scope

### Individual Scan window doesn't open
- Make sure the endpoint is configured and saved first
- Check the **Errors** tab of the extension for details

---

## License

MIT — see LICENSE for details.
