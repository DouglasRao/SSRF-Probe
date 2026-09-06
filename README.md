# SSRF Probe — Burp Suite Extension

> Configurable out-of-band (OOB) callback testing for SSRF — works with **Burp Suite Community**.
> You define the callback endpoint — ngrok, webhook.site, interactsh, or any other.

---

## Highlights

- Works with **Burp Suite Community**
- **You choose** the OOB callback endpoint — ngrok, webhook.site, interactsh, your own server
- If a public OOB service is blocked by a WAF, point it at your own server
- Full injection log with canary map
- Choose exactly which headers to inject

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
CF-Connecting-IP           Client-IP                  Cluster-Client-IP
Contact                    Destination                Fastly-Client-Ip
Forwarded                  Origin                     Referer
True-Client-IP             Via                        X-Backend-Host
X-Client-IP                X-Custom-IP-Authorization  X-Forwarded
X-Forwarded-For            X-Forwarded-Host           X-Host
X-HTTP-Host-Override       X-Original-Host            X-Original-URL
X-Originating-IP           X-ProxyUser-Ip             X-Real-IP
X-Remote-Addr              X-Remote-IP                X-Rewrite-URL
X-Wap-Profile
```

You can deselect individually or add custom headers.

### Header payload style
Headers that semantically take a **hostname** (`Host`, `Via`, `X-Backend-Host`, `X-Forwarded-Host`, `X-Host`, `X-HTTP-Host-Override`, `X-Original-Host`) receive a hostname-only payload (e.g. `CANARY.your-domain.com`); all other headers receive the full URL payload (e.g. `http://CANARY.your-domain.com/x7k2p9qr`).

### ⚠️ About the Host header
`Host` is present in the list but is **NOT selected by default**: replacing the Host header breaks virtual-host routing to the target on every request. Only select it deliberately for specific tests.

---

## Auto-Detected Parameters

The extension detects parameters whose name suggests SSRF and rewrites their value with the payload:

`action, api, callback, continue, data, dest, destination, domain, endpoint, feed, fetch, file, forward, goto, host, href, image, img, link, load, next, notify, open, page, path, ping, proxy, redirect, ref, referrer, request, return, service, site, source, src, target, uri, url, webhook`

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
| **canarytokens.org** | ✅ | ✅ | ✅ | Permanent |
| **Interactsh** (projectdiscovery) | ✅ | ✅ | ✅ | Session |
| **ngrok** | ✅ | ❌ | ✅ | Session |
| **Webhook.site** | ✅ | ✅ (dnshook) | ✅ | 7 days |
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
