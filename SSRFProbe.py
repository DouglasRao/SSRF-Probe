# -*- coding: utf-8 -*-
"""
SSRFProbe.py - Burp Suite Extension (single file)
==================================================
Alternative to Collaborator Everywhere for SSRF testing.

Key differences:
  * Works with Burp Community (no Pro required)
  * You define the callback endpoint (ngrok, webhook.site, oastify, etc.)
  * Automatically injects SSRF payloads in all headers and parameters
  * Built-in configuration panel inside Burp UI
  * Log of all injected requests

Load in Burp: Extensions > Add > Type: Python > select this file
Requirement: Jython 2.7 (Extender > Options > Python Environment)
"""

from burp import (IBurpExtender, ITab, IHttpListener, IProxyListener,
                  IContextMenuFactory, IHttpRequestResponse)

import os, sys, json, threading, re
from java.awt import BorderLayout, FlowLayout, Color, Font, Dimension, GridBagLayout, GridBagConstraints, Insets
from java.awt.event import MouseAdapter
from java.io import ByteArrayOutputStream, PrintWriter
from javax.swing import (JPanel, JButton, JLabel, JScrollPane, JTextArea,
    JTextField, SwingUtilities, BorderFactory, SwingConstants,
    JTabbedPane, JCheckBox, JTable, JComboBox, Box, BoxLayout,
    JOptionPane, JSplitPane, DefaultListModel, JList, JMenuItem,
    JPopupMenu, ListSelectionModel, JComponent)
from javax.swing.border import EmptyBorder, TitledBorder
from javax.swing.table import DefaultTableModel
from java.lang import System

EXT_NAME = "SSRF Probe"
EXT_VER  = "1.0"

C_BG   = Color(0x2B, 0x2B, 0x2B)
C_TB   = Color(0x3C, 0x3F, 0x41)
C_ACC  = Color(0xE8, 0x58, 0x1A)
C_FG   = Color(0xCC, 0xCC, 0xCC)
C_DIM  = Color(0x88, 0x88, 0x88)
C_EDIT = Color(0x1E, 0x1E, 0x1E)
C_RED  = Color(0xFF, 0x60, 0x60)
C_GRN  = Color(0x60, 0xCC, 0x60)

_SSRF_HEADERS = [
    "X-Forwarded-For","X-Forwarded-Host","X-Host","X-Custom-IP-Authorization",
    "X-Original-URL","X-Rewrite-URL","X-Real-IP","Client-IP","True-Client-IP",
    "Cluster-Client-IP","X-ProxyUser-Ip","Via","Forwarded","X-Originating-IP",
    "X-Remote-IP","X-Remote-Addr","X-Client-IP","CF-Connecting-IP",
    "Fastly-Client-Ip","X-Forwarded","X-Wap-Profile","Contact","Referer",
    "Origin","X-Original-Host","X-Backend-Host","Destination",
    "X-HTTP-Host-Override","Host",
]

_SSRF_PARAM_PATTERNS = [
    "url","uri","path","src","source","dest","destination",
    "redirect","redirectUrl","redirect_url","redirectUri","redirect_uri",
    "return","returnUrl","return_url","returnTo","return_to",
    "next","nextUrl","next_url","target","targetUrl","target_url",
    "link","linkUrl","link_url","href","action","goto",
    "site","page","ref","referrer","callback","callbackUrl","callback_url",
    "proxy","proxyUrl","proxy_url","fetch","load","file",
    "image","imageUrl","image_url","img","imgUrl","img_url",
    "request","requestUrl","request_url","domain","host",
    "endpoint","service","api","apiUrl","api_url","continue",
    "forward","forwardUrl","forward_url","open","window",
    "data","feed","webhook","notify","ping",
]

# Headers that semantically take a HOSTNAME (not a full URL). These receive a
# hostname-only payload ("CANARY.domain.tld"), which is what servers expect.
# All other headers receive the full URL payload ("http://CANARY.domain.tld/...").
_HOST_STYLE = set(h.lower() for h in [
    "Host","X-Forwarded-Host","X-Host","X-Original-Host",
    "X-Backend-Host","X-HTTP-Host-Override","Via",
])

def _mk_btn(txt, tip=None, bg=C_TB, fg=C_FG):
    from javax.swing import JButton
    from java.awt import Cursor
    b = JButton(txt)
    b.setBackground(bg); b.setForeground(fg)
    b.setFocusPainted(False); b.setBorderPainted(False); b.setOpaque(True)
    b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
    if tip: b.setToolTipText(tip)
    return b

def _mk_lbl(txt, c=C_FG, bold=False, sz=12):
    l = JLabel(txt); l.setForeground(c)
    l.setFont(Font("SansSerif", Font.BOLD if bold else Font.PLAIN, sz))
    return l

def _mk_field(placeholder="", w=30):
    f = JTextField(w)
    f.setBackground(C_EDIT); f.setForeground(C_FG); f.setCaretColor(C_FG)
    f.setFont(Font("Monospaced", Font.PLAIN, 12))
    if placeholder: f.setToolTipText(placeholder)
    return f

def _mk_area(rows=8):
    a = JTextArea(rows, 60)
    a.setBackground(C_EDIT); a.setForeground(C_FG); a.setCaretColor(C_FG)
    a.setFont(Font("Monospaced", Font.PLAIN, 12))
    a.setLineWrap(True); a.setWrapStyleWord(False)
    return a

import random, string, hashlib, time

def _make_canary(length=8):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

# Supported endpoint modes: (key, display_name, format, hint, value_label)
# Kept in alphabetical order by display_name (the order shown in the Mode combo).
ENDPOINT_MODES = [
    ("burp_collab",  "Burp Collaborator (oastify)", "CANARY.DOMAIN.oastify.com",          "Paste your collaborator domain", "Collaborator domain:"),
    ("custom_dns",   "Custom DNS",                  "CANARY.YOUR_DOMAIN",                 "Your controlled domain (e.g. mysite.com)", "Domain:"),
    ("custom_http",  "Custom HTTP",                 "https://YOUR_HOST/CANARY",           "Full URL of your server", "Full URL:"),
    ("interactsh",   "Interactsh (oast.fun)",       "CANARY.SUBDOMAIN.oast.fun",          "Paste your interactsh subdomain", "Interactsh subdomain:"),
    ("localhost",    "Localhost / Internal SSRF",   "Internal IP presets",                "Select internal target", "Internal target:"),
    ("ngrok_http",   "ngrok (HTTP OOB)",            "https://SUBDOMAIN.ngrok.io/CANARY",  "Paste your ngrok subdomain (e.g. abc123.ngrok.io)", "ngrok URL:"),
    ("webhook_dns",  "Webhook.site DNS Hook",      "CANARY.*.dnshook.site",             "Paste everything after *. e.g. 8f713526-7500-4513-8662-40f4f97d6e2d.dnshook.site", "DNS hook:"),
]
MODE_KEYS = [m[0] for m in ENDPOINT_MODES]

LOCALHOST_PRESETS = [
    "127.0.0.1", "localhost", "0.0.0.0", "[::1]",
    "169.254.169.254",                           # AWS metadata
    "metadata.google.internal",                  # GCP metadata
    "100.100.100.200",                           # Alibaba metadata
    "192.168.0.1", "10.0.0.1", "172.16.0.1",
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
]

_CB      = None
_HELPERS = None
_STATE   = {
    "enabled":          False,
    "endpoint_mode":    "webhook_dns",
    "endpoint_value":   "",
    "endpoint":         "",
    "inject_headers":   True,
    "inject_params":    True,
    "scope_only":       False,
    # Host is NOT selected by default: replacing the Host header breaks
    # virtual-host routing to the target on every proxied request. It stays
    # available in the list for deliberate, manual use.
    "selected_headers": [h for h in _SSRF_HEADERS if h.lower() != "host"],
    "log": [],
    "canary_map": {},
}
_LOG_LOCK = threading.Lock()

def _build_payload(canary, host_style=False):
    mode  = _STATE.get("endpoint_mode", "custom_http")
    value = _STATE.get("endpoint_value", "").strip().rstrip("/")
    if not value: return None
    if mode == "webhook_dns":
        base = value.lstrip("*").lstrip(".")
        url = "http://%s.%s" % (canary, base)
    elif mode == "interactsh":
        base = value if "." in value else value + ".oast.fun"
        url = "http://%s.%s" % (canary, base)
    elif mode == "burp_collab":
        url = "http://%s.%s" % (canary, value)
    elif mode == "ngrok_http":
        base = value if value.startswith("http") else "https://" + value
        url = "%s/%s" % (base.rstrip("/"), canary)
    elif mode == "custom_dns":
        url = "http://%s.%s" % (canary, value)
    elif mode == "custom_http":
        base = value if value.startswith("http") else "http://" + value
        url = "%s/%s" % (base.rstrip("/"), canary)
    elif mode == "localhost":
        url = value if value.startswith("http") else "http://" + value
    else:
        base = value if value.startswith("http") else "http://" + value
        url = "%s/%s" % (base.rstrip("/"), canary)
    if host_style:
        return _payload_host(url)
    return url

def _payload_host(url):
    """Strip scheme and path from a URL, leaving host[:port] only."""
    rest = url.split("://", 1)[1] if "://" in url else url
    return rest.split("/", 1)[0]

def _inject_request(request_bytes, http_service):
    if not _STATE.get("endpoint_value","").strip(): return None
    try:
        req_info   = _HELPERS.analyzeRequest(http_service, request_bytes)
        headers    = list(req_info.getHeaders())
        params     = list(req_info.getParameters())
        body_off   = req_info.getBodyOffset()
        body_bytes = request_bytes[body_off:]   # Java byte[] slice
        canary     = _make_canary()
        payload    = _build_payload(canary)
        if not payload: return None
        url_str    = str(req_info.getUrl())
        injected   = []
        new_headers = list(headers)

        if _STATE["inject_headers"] and _STATE["selected_headers"]:
            selected = set(h.lower() for h in _STATE["selected_headers"])
            # Drop the originals of the headers we are about to inject.
            # Matching is case-insensitive; the first element is the request
            # line and never matches a header name.
            new_headers = [h for h in new_headers
                           if h.split(":", 1)[0].strip().lower() not in selected]
            for hname in _STATE["selected_headers"]:
                hc = _make_canary()
                # Host-style headers get a hostname-only payload ("CANARY.dom"),
                # URL-ish headers get the full URL ("http://CANARY.dom/...").
                hp = _build_payload(hc, hname.strip().lower() in _HOST_STYLE)
                new_headers.append("%s: %s" % (hname, hp))
                injected.append({"type": "header", "name": hname, "canary": hc})
                _register_canary(hc, url_str, "header:" + hname)

        body_final = None
        if _STATE["inject_params"] and params:
            # Lossless byte <-> str round-trip (Jython-safe; chr()+utf-8 would
            # expand every byte >= 0x80 and corrupt binary bodies).
            body_str      = _HELPERS.bytesToString(body_bytes)
            modified_body = body_str
            body_changed  = False
            for p in params:
                name  = p.getName()
                pname = name.lower()
                if not any(pat.lower() in pname or pname in pat.lower() for pat in _SSRF_PARAM_PATTERNS):
                    continue
                pc = _make_canary(); pp = _build_payload(pc); ptype = p.getType()
                if ptype == 0:
                    # URL parameter: rewrite the value in the request line.
                    pat0 = re.compile(r'([?&])' + re.escape(name) + r'=[^&#\s]*')
                    def _r0(m):
                        return m.group(1) + name + '=' + _HELPERS.urlEncode(pp)
                    line, n = pat0.subn(_r0, new_headers[0], count=1)
                    if n:
                        new_headers[0] = line
                        injected.append({"type":"url_param","name":name,"canary":pc})
                        _register_canary(pc, url_str, "url_param:" + name)
                elif ptype == 1:
                    # Body parameter (application/x-www-form-urlencoded).
                    pat1 = re.compile(r'(^|&)' + re.escape(name) + r'=[^&]*')
                    def _r1(m):
                        return m.group(1) + name + '=' + _HELPERS.urlEncode(pp)
                    modified_body, n = pat1.subn(_r1, modified_body, count=1)
                    if n:
                        body_changed = True
                        injected.append({"type":"body_param","name":name,"canary":pc})
                        _register_canary(pc, url_str, "body_param:" + name)
                elif ptype == 2:
                    # JSON parameter: rewrite the string value of "name": "value".
                    m = re.search(r'("' + re.escape(name) + r'"\s*:\s*")(?:[^"\\]|\\.)*(")', modified_body)
                    if not m and "." in name:
                        # Burp may report nested keys as "outer.inner"; retry on the leaf key.
                        leaf = name.split(".")[-1]
                        m = re.search(r'("' + re.escape(leaf) + r'"\s*:\s*")(?:[^"\\]|\\.)*(")', modified_body)
                    if m:
                        modified_body = modified_body[:m.end(1)] + pp + modified_body[m.start(2):]
                        body_changed = True
                        injected.append({"type":"json_param","name":name,"canary":pc})
                        _register_canary(pc, url_str, "json_param:" + name)
            if body_changed:
                body_final = _HELPERS.stringToBytes(modified_body)
            elif len(body_bytes) > 0:
                body_final = body_bytes   # untouched: pass the original Java slice
        elif len(body_bytes) > 0:
            body_final = body_bytes

        if not injected: return None

        rebuilt = _HELPERS.buildHttpMessage(new_headers, body_final)
        _add_log({"url":url_str,"injected":injected,"canary":canary,"payload":payload,
                  "time":time.strftime("%H:%M:%S"),"req_bytes":rebuilt,"http_service":http_service})
        return rebuilt
    except Exception as ex:
        _log_err("Inject error: " + str(ex))
        return None

def _register_canary(canary, url, location):
    with _LOG_LOCK:
        _STATE["canary_map"][canary] = {"url":url,"location":location,"time":time.strftime("%Y-%m-%d %H:%M:%S")}
        # Bound memory on long sessions (canary_map is never trimmed elsewhere).
        while len(_STATE["canary_map"]) > 2000:
            try: _STATE["canary_map"].popitem()
            except Exception: break

def _add_log(entry):
    with _LOG_LOCK:
        _STATE["log"].insert(0, entry)
        if len(_STATE["log"]) > 500: _STATE["log"] = _STATE["log"][:500]

def _log_err(msg):
    if _CB: _CB.getStderr().write(("[%s] %s\n" % (EXT_NAME, msg)).encode("utf-8"))

def _log_out(msg):
    if _CB: _CB.getStdout().write(("[%s] %s\n" % (EXT_NAME, msg)).encode("utf-8"))


class ConfigPanel(JPanel):
    def __init__(self, log_panel):
        super(ConfigPanel, self).__init__(BorderLayout())
        self._log_panel = log_panel
        self.setBackground(C_BG)
        self._build_ui()

    def _build_ui(self):
        main = JPanel()
        main.setLayout(BoxLayout(main, BoxLayout.Y_AXIS))
        main.setBackground(C_BG)
        main.setBorder(EmptyBorder(12,12,12,12))

        # Endpoint section
        ep = JPanel(); ep.setLayout(BoxLayout(ep, BoxLayout.Y_AXIS))
        ep.setBackground(C_BG)
        ep.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(C_ACC,1)," Callback Endpoint (SSRF) "))
        ep.setAlignmentX(JComponent.LEFT_ALIGNMENT)

        row_mode = JPanel(FlowLayout(FlowLayout.LEFT,6,4)); row_mode.setBackground(C_BG)
        row_mode.add(_mk_lbl("Mode:"))
        mode_names = [m[1] for m in ENDPOINT_MODES]
        self._mode_combo = JComboBox(mode_names)
        self._mode_combo.setBackground(C_EDIT); self._mode_combo.setForeground(C_FG)
        self._mode_combo.setFont(Font("SansSerif",Font.PLAIN,12))
        cur = _STATE.get("endpoint_mode","webhook_dns")
        if cur in MODE_KEYS: self._mode_combo.setSelectedIndex(MODE_KEYS.index(cur))
        row_mode.add(self._mode_combo); ep.add(row_mode)

        row_val = JPanel(FlowLayout(FlowLayout.LEFT,6,4)); row_val.setBackground(C_BG)
        self._val_lbl = _mk_lbl("Value:", C_FG)
        row_val.add(self._val_lbl)
        self._ep_field = _mk_field("Paste the service-specific value here", 42)
        self._ep_field.setText(_STATE.get("endpoint_value",""))
        row_val.add(self._ep_field)
        self._btn_save = _mk_btn(" Save ", "Save configuration")
        row_val.add(self._btn_save); ep.add(row_val)

        row_prev = JPanel(FlowLayout(FlowLayout.LEFT,6,2)); row_prev.setBackground(C_BG)
        row_prev.add(_mk_lbl("Format:", C_DIM, sz=11))
        self._fmt_lbl = _mk_lbl("", C_ACC, sz=11)
        row_prev.add(self._fmt_lbl); ep.add(row_prev)

        self._local_panel = JPanel(FlowLayout(FlowLayout.LEFT,4,2)); self._local_panel.setBackground(C_BG)
        self._local_panel.add(_mk_lbl("Presets:", C_DIM, sz=11))
        from java.awt.event import ActionListener as _AL2
        ep_ref = self._ep_field
        for ip in LOCALHOST_PRESETS[:8]:
            btn = _mk_btn(ip, "Use " + ip); btn.setFont(Font("Monospaced",Font.PLAIN,10))
            ip_v = ip
            class _IpClick(_AL2):
                def __init__(s,v): s.v=v
                def actionPerformed(s,e): ep_ref.setText(s.v)
            btn.addActionListener(_IpClick(ip_v)); self._local_panel.add(btn)
        self._local_panel.setVisible(False); ep.add(self._local_panel)

        row_hint = JPanel(FlowLayout(FlowLayout.LEFT,6,2)); row_hint.setBackground(C_BG)
        self._hint_lbl = _mk_lbl("", C_DIM, sz=10); row_hint.add(self._hint_lbl); ep.add(row_hint)

        cp_ref = self
        from java.awt.event import ActionListener as _AL3
        class _ModeAL(_AL3):
            def actionPerformed(s,e): cp_ref._on_mode_change()
        self._mode_combo.addActionListener(_ModeAL())
        self._on_mode_change()
        main.add(ep); main.add(Box.createVerticalStrut(10))

        # Injection options
        opt = JPanel(); opt.setLayout(BoxLayout(opt, BoxLayout.Y_AXIS))
        opt.setBackground(C_BG)
        opt.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(C_ACC,1)," Injection Options "))
        opt.setAlignmentX(JComponent.LEFT_ALIGNMENT)
        row3 = JPanel(FlowLayout(FlowLayout.LEFT,12,4)); row3.setBackground(C_BG)
        self._chk_enabled = JCheckBox("Interception active"); self._chk_enabled.setBackground(C_BG); self._chk_enabled.setForeground(C_FG); self._chk_enabled.setSelected(_STATE["enabled"])
        self._chk_headers = JCheckBox("Inject in HTTP Headers"); self._chk_headers.setBackground(C_BG); self._chk_headers.setForeground(C_FG); self._chk_headers.setSelected(_STATE["inject_headers"])
        self._chk_params  = JCheckBox("Inject in Parameters (query/body)"); self._chk_params.setBackground(C_BG); self._chk_params.setForeground(C_FG); self._chk_params.setSelected(_STATE["inject_params"])
        self._chk_scope   = JCheckBox("Scope only"); self._chk_scope.setBackground(C_BG); self._chk_scope.setForeground(C_FG); self._chk_scope.setSelected(False)
        _STATE["scope_only"] = False
        for chk in [self._chk_enabled,self._chk_headers,self._chk_params,self._chk_scope]: row3.add(chk)
        opt.add(row3); main.add(opt); main.add(Box.createVerticalStrut(10))

        # Headers list
        hdr = JPanel(BorderLayout(6,4)); hdr.setBackground(C_BG)
        hdr.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(C_ACC,1)," Headers to Inject "))
        hdr.setAlignmentX(JComponent.LEFT_ALIGNMENT); hdr.setMaximumSize(Dimension(900,180))
        self._hdr_model = DefaultListModel()
        for h in _SSRF_HEADERS: self._hdr_model.addElement(h)
        self._hdr_list = JList(self._hdr_model)
        self._hdr_list.setBackground(C_EDIT); self._hdr_list.setForeground(C_FG)
        self._hdr_list.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._hdr_list.setFont(Font("Monospaced",Font.PLAIN,11))
        # Select everything except Host: replacing Host breaks virtual-host
        # routing to the target on every proxied request.
        host_idx = _SSRF_HEADERS.index("Host") if "Host" in _SSRF_HEADERS else -1
        last = self._hdr_model.size()-1
        if host_idx < 0:
            self._hdr_list.setSelectionInterval(0, last)
        else:
            if host_idx > 0: self._hdr_list.addSelectionInterval(0, host_idx-1)
            if host_idx < last: self._hdr_list.addSelectionInterval(host_idx+1, last)
        self._hdr_list.setLayoutOrientation(JList.HORIZONTAL_WRAP); self._hdr_list.setVisibleRowCount(4)
        hdr_scroll = JScrollPane(self._hdr_list); hdr_scroll.setBackground(C_EDIT); hdr_scroll.setBorder(None); hdr_scroll.setPreferredSize(Dimension(860,140))
        hdr_btns = JPanel(FlowLayout(FlowLayout.LEFT,4,4)); hdr_btns.setBackground(C_BG)
        self._btn_all   = _mk_btn("All",    "Select all headers (careful: replacing Host breaks routing to the target)")
        self._btn_none  = _mk_btn("None",   "Deselect all")
        self._btn_add_h = _mk_btn("+ Header","Add custom header")
        hdr_btns.add(self._btn_all); hdr_btns.add(self._btn_none); hdr_btns.add(self._btn_add_h)
        hdr.add(hdr_scroll, BorderLayout.CENTER); hdr.add(hdr_btns, BorderLayout.SOUTH)
        main.add(hdr); main.add(Box.createVerticalStrut(10))

        # Control buttons
        ctrl = JPanel(FlowLayout(FlowLayout.LEFT,8,6)); ctrl.setBackground(C_BG)
        self._btn_toggle = _mk_btn(" ENABLE INTERCEPTION ", "Toggle automatic injection", C_GRN, Color.BLACK)
        self._btn_clear  = _mk_btn(" Clear Log ", "Clear all injection records")
        ctrl.add(self._btn_toggle); ctrl.add(self._btn_clear); main.add(ctrl)

        scroll = JScrollPane(main); scroll.setBorder(None); scroll.getViewport().setBackground(C_BG)
        self.add(scroll, BorderLayout.CENTER)

        self._status = _mk_lbl("  Status: INACTIVE  |  Endpoint: (not configured)", C_RED, sz=11)
        sb = JPanel(FlowLayout(FlowLayout.LEFT,4,4)); sb.setBackground(C_TB); sb.add(self._status)
        self.add(sb, BorderLayout.SOUTH)

        self._btn_save.addActionListener(lambda e: self._save())
        self._btn_toggle.addActionListener(lambda e: self._toggle())
        self._btn_clear.addActionListener(lambda e: self._clear_log())
        self._btn_all.addActionListener(lambda e: self._hdr_list.setSelectionInterval(0, self._hdr_model.size()-1))
        self._btn_none.addActionListener(lambda e: self._hdr_list.clearSelection())
        self._btn_add_h.addActionListener(lambda e: self._add_header())
        self._update_status()

    def _on_mode_change(self):
        idx = self._mode_combo.getSelectedIndex()
        if idx < 0 or idx >= len(ENDPOINT_MODES): return
        key,name,fmt,hint,vlabel = ENDPOINT_MODES[idx]
        self._val_lbl.setText(vlabel)
        self._fmt_lbl.setText(fmt); self._hint_lbl.setText(hint)
        self._local_panel.setVisible(key == "localhost")
        self.revalidate(); self.repaint()

    def _save(self):
        idx = self._mode_combo.getSelectedIndex()
        mode_key = MODE_KEYS[idx] if idx >= 0 else "custom_http"
        val = self._ep_field.getText().strip()
        _STATE["endpoint_mode"] = mode_key; _STATE["endpoint_value"] = val; _STATE["endpoint"] = val
        _STATE["inject_headers"] = self._chk_headers.isSelected()
        _STATE["inject_params"]  = self._chk_params.isSelected()
        _STATE["scope_only"]     = self._chk_scope.isSelected()
        sel = self._hdr_list.getSelectedValuesList()
        _STATE["selected_headers"] = list(sel) if sel else []
        self._update_status()
        _log_out("Saved. Mode: %s  Value: %s" % (mode_key, val))

    def _toggle(self):
        self._save()
        if not _STATE.get("endpoint_value","").strip():
            JOptionPane.showMessageDialog(self,"Configure and save the endpoint first!","Endpoint not configured",JOptionPane.WARNING_MESSAGE)
            return
        _STATE["enabled"] = not _STATE["enabled"]
        self._chk_enabled.setSelected(_STATE["enabled"])
        self._update_status()
        _log_out("Interception: " + ("ACTIVE" if _STATE["enabled"] else "INACTIVE"))

    def _clear_log(self):
        with _LOG_LOCK: _STATE["log"]=[]; _STATE["canary_map"]={}
        if self._log_panel: self._log_panel.refresh()

    def _add_header(self):
        name = JOptionPane.showInputDialog(self,"Custom header name:","Add Header",JOptionPane.PLAIN_MESSAGE)
        if name and name.strip():
            self._hdr_model.addElement(name.strip())
            idx = self._hdr_model.size()-1
            self._hdr_list.addSelectionInterval(idx,idx)

    def _update_status(self):
        ep = _STATE.get("endpoint_value","") or "(not configured)"
        mode_key = _STATE.get("endpoint_mode","")
        mode_name = mode_key
        for m in ENDPOINT_MODES:
            if m[0] == mode_key: mode_name = m[1]; break
        ep_display = "[%s] %s" % (mode_name, ep) if ep != "(not configured)" else ep
        if _STATE["enabled"]:
            self._status.setText("  Status: ACTIVE  |  " + ep_display); self._status.setForeground(C_GRN)
            self._btn_toggle.setText(" DISABLE INTERCEPTION "); self._btn_toggle.setBackground(C_RED); self._btn_toggle.setForeground(Color.WHITE)
        else:
            self._status.setText("  Status: INACTIVE  |  " + ep_display); self._status.setForeground(C_RED)
            self._btn_toggle.setText(" ENABLE INTERCEPTION "); self._btn_toggle.setBackground(C_GRN); self._btn_toggle.setForeground(Color.BLACK)


class LogPanel(JPanel):
    def __init__(self):
        super(LogPanel,self).__init__(BorderLayout())
        self.setBackground(C_BG); self._build_ui()

    def _build_ui(self):
        cols = ["Time","URL","Injections","Sample Payload","Canary"]
        self._model = DefaultTableModel(cols,0)
        self._table = JTable(self._model)
        self._table.setBackground(C_EDIT); self._table.setForeground(C_FG); self._table.setGridColor(C_TB)
        self._table.setFont(Font("Monospaced",Font.PLAIN,11)); self._table.setRowHeight(20)
        self._table.getTableHeader().setBackground(C_TB); self._table.getTableHeader().setForeground(C_FG)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(70)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(350)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(280)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(80)
        tbl_scroll = JScrollPane(self._table); tbl_scroll.setBackground(C_EDIT); tbl_scroll.setBorder(None)

        self._detail = _mk_area(6); self._detail.setEditable(False)
        det_scroll = JScrollPane(self._detail)
        det_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(C_ACC,1)," Injection Details "))
        det_scroll.setPreferredSize(Dimension(0,140))

        split = JSplitPane(JSplitPane.VERTICAL_SPLIT, tbl_scroll, det_scroll)
        split.setResizeWeight(0.72); split.setDividerSize(4); split.setBackground(C_BG)
        self.add(split, BorderLayout.CENTER)

        tb = JPanel(FlowLayout(FlowLayout.LEFT,6,4)); tb.setBackground(C_TB)
        self._lbl_count  = _mk_lbl("  0 requests injected", C_FG, sz=11)
        self._btn_refresh = _mk_btn(" Refresh ", "Reload log")
        self._btn_export  = _mk_btn(" Export Canaries ", "Copy canary map to clipboard")
        self._btn_repe    = _mk_btn(" Send to Repeater ", "Send injected request to Repeater", C_ACC, Color.WHITE)
        tb.add(self._lbl_count); tb.add(self._btn_refresh); tb.add(self._btn_export); tb.add(self._btn_repe)
        self.add(tb, BorderLayout.NORTH)
        self._btn_refresh.addActionListener(lambda e: self.refresh())
        self._btn_export.addActionListener(lambda e: self._export_canaries())
        self._btn_repe.addActionListener(lambda e: self._send_to_repeater())

        lp = self
        class _RowClick(MouseAdapter):
            def mouseClicked(self2, e):
                row = lp._table.getSelectedRow()
                if 0 <= row < len(_STATE["log"]):
                    entry = _STATE["log"][row]
                    lines = ["URL: " + entry.get("url",""), "Time: " + entry.get("time",""),
                             "Sample payload: " + entry.get("payload",""), "", "Injections:"]
                    for inj in entry.get("injected",[]):
                        lines.append("  [%s] %s  ->  canary: %s" % (inj.get("type",""),inj.get("name",""),inj.get("canary","")))
                    lp._detail.setText("\n".join(lines))
        self._table.addMouseListener(_RowClick())

    def refresh(self):
        def _do():
            self._model.setRowCount(0)
            with _LOG_LOCK: log_copy = list(_STATE["log"])
            for e in log_copy:
                self._model.addRow([e.get("time",""),e.get("url",""),str(len(e.get("injected",[]))),e.get("payload",""),e.get("canary","")])
            self._lbl_count.setText("  %d requests injected" % len(log_copy))
        SwingUtilities.invokeLater(_do)

    def _send_to_repeater(self):
        row = self._table.getSelectedRow()
        if row < 0:
            JOptionPane.showMessageDialog(self,"Select a row first.","No row selected",JOptionPane.WARNING_MESSAGE); return
        with _LOG_LOCK:
            if row >= len(_STATE["log"]): return
            entry = _STATE["log"][row]
        rb = entry.get("req_bytes"); svc = entry.get("http_service")
        if not rb or not svc:
            JOptionPane.showMessageDialog(self,"Request data not available.","Error",JOptionPane.ERROR_MESSAGE); return
        try:
            _CB.sendToRepeater(svc.getHost(),svc.getPort(),svc.getProtocol()=="https",rb,"SSRF-"+entry.get("canary",""))
        except Exception as ex:
            JOptionPane.showMessageDialog(self,"Error: "+str(ex),"Error",JOptionPane.ERROR_MESSAGE)

    def _export_canaries(self):
        with _LOG_LOCK: cmap = dict(_STATE["canary_map"])
        if not cmap:
            JOptionPane.showMessageDialog(self,"No canaries registered yet.","Canaries",JOptionPane.INFORMATION_MESSAGE); return
        lines = ["Canary Map - SSRF Probe","="*40]
        for c,info in cmap.items():
            lines += ["Canary: "+c,"  URL:      "+info.get("url",""),"  Location: "+info.get("location",""),"  Time:     "+info.get("time",""),""]
        from java.awt import Toolkit
        from java.awt.datatransfer import StringSelection
        Toolkit.getDefaultToolkit().getSystemClipboard().setContents(StringSelection("\n".join(lines)),None)
        JOptionPane.showMessageDialog(self,"%d canaries copied to clipboard." % len(cmap),"Exported",JOptionPane.INFORMATION_MESSAGE)


class ScanPanel(JPanel, ITab):
    def __init__(self, title):
        super(ScanPanel,self).__init__(BorderLayout())
        self.setBackground(C_BG); self._title=title; self._rows=[]; self._build_ui()

    def getTabCaption(self): return self._title
    def getUiComponent(self): return self

    def _build_ui(self):
        cols = ["#","Header","Status","Size","Time(ms)","Canary","Payload"]
        self._model = DefaultTableModel(cols,0)
        self._table = JTable(self._model)
        self._table.setBackground(C_EDIT); self._table.setForeground(C_FG); self._table.setGridColor(C_TB); self._table.setRowHeight(20)
        self._table.setFont(Font("Monospaced",Font.PLAIN,11))
        self._table.getTableHeader().setBackground(C_TB); self._table.getTableHeader().setForeground(C_FG)
        self._table.getColumnModel().getColumn(0).setPreferredWidth(40)
        self._table.getColumnModel().getColumn(1).setPreferredWidth(180)
        self._table.getColumnModel().getColumn(2).setPreferredWidth(60)
        self._table.getColumnModel().getColumn(3).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(4).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(5).setPreferredWidth(80)
        self._table.getColumnModel().getColumn(6).setPreferredWidth(260)
        tbl_scroll = JScrollPane(self._table); tbl_scroll.setBorder(None)

        self._req_area  = _mk_area(10); self._req_area.setEditable(False)
        self._resp_area = _mk_area(10); self._resp_area.setEditable(False)
        req_scroll  = JScrollPane(self._req_area)
        resp_scroll = JScrollPane(self._resp_area)
        req_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(C_ACC,1)," Request "))
        resp_scroll.setBorder(BorderFactory.createTitledBorder(BorderFactory.createLineBorder(C_ACC,1)," Response "))
        req_resp = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,req_scroll,resp_scroll)
        req_resp.setResizeWeight(0.5); req_resp.setDividerSize(4); req_resp.setBackground(C_BG)
        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT,tbl_scroll,req_resp)
        main_split.setResizeWeight(0.5); main_split.setDividerSize(4); main_split.setBackground(C_BG)

        self._status_lbl = _mk_lbl("  Waiting...", C_DIM, sz=11)
        sb = JPanel(FlowLayout(FlowLayout.LEFT,4,2)); sb.setBackground(C_TB); sb.add(self._status_lbl)
        tb = JPanel(FlowLayout(FlowLayout.LEFT,6,4)); tb.setBackground(C_TB)
        self._lbl_prog = _mk_lbl("  0 headers tested", C_FG, sz=11); tb.add(self._lbl_prog)
        self.add(main_split,BorderLayout.CENTER); self.add(sb,BorderLayout.SOUTH); self.add(tb,BorderLayout.NORTH)

        sp = self
        class _Click(MouseAdapter):
            def mouseClicked(self2,e):
                row = sp._table.getSelectedRow()
                if 0 <= row < len(sp._rows):
                    d = sp._rows[row]
                    sp._req_area.setText(d.get("req_str","")); sp._resp_area.setText(d.get("resp_str",""))
                    sp._req_area.setCaretPosition(0); sp._resp_area.setCaretPosition(0)
        self._table.addMouseListener(_Click())

    def add_result(self, idx, header, canary, payload, status, length, elapsed_ms, req_str, resp_str):
        def _do():
            self._rows.append({"req_str":req_str,"resp_str":resp_str})
            self._model.addRow([str(idx),header,str(status),str(length),str(elapsed_ms),canary,payload])
            self._lbl_prog.setText("  %d headers tested" % len(self._rows))
            self._table.setRowSelectionInterval(self._model.getRowCount()-1,self._model.getRowCount()-1)
        SwingUtilities.invokeLater(_do)

    def set_status(self, msg):
        SwingUtilities.invokeLater(lambda: self._status_lbl.setText("  " + msg))


def _run_scan(request_bytes, http_service, headers_to_test, scan_panel):
    try:
        req_info  = _HELPERS.analyzeRequest(http_service, request_bytes)
        orig_hdrs = list(req_info.getHeaders())
        body_raw  = request_bytes[req_info.getBodyOffset():]   # Java byte[] slice
        body_final = body_raw if len(body_raw) > 0 else None
        total = len(headers_to_test)
        scan_panel.set_status("Starting scan of %d headers..." % total)
        for idx, hname in enumerate(headers_to_test, 1):
            try:
                hl = hname.strip().lower()
                canary = _make_canary()
                payload = _build_payload(canary, hl in _HOST_STYLE)
                if not payload: continue
                new_hdrs = [h for h in orig_hdrs if h.split(":", 1)[0].strip().lower() != hl]
                new_hdrs.append("%s: %s" % (hname, payload))
                modified = _HELPERS.buildHttpMessage(new_hdrs, body_final)
                scan_panel.set_status("[%d/%d] Testing: %s" % (idx, total, hname))
                t0 = time.time()
                try:
                    response = _CB.makeHttpRequest(http_service, modified)
                    elapsed  = int((time.time()-t0)*1000)
                    resp_bytes = response.getResponse() if response else None
                    if resp_bytes:
                        resp_info   = _HELPERS.analyzeResponse(resp_bytes)
                        status_code = resp_info.getStatusCode()
                        resp_len    = len(resp_bytes)
                        resp_str    = "".join([chr(resp_bytes[i]&0xFF) for i in range(min(len(resp_bytes),8192))])
                    else:
                        status_code=0; resp_len=0; resp_str="(no response)"
                    req_str = "".join([chr(modified[i]&0xFF) for i in range(min(len(modified),8192))])
                    scan_panel.add_result(idx,hname,canary,payload,status_code,resp_len,elapsed,req_str,resp_str)
                except Exception as ex:
                    scan_panel.add_result(idx,hname,canary,payload,0,0,0,str(ex),"Request error")
            except Exception as ex2:
                _log_err("scan %s: %s" % (hname,str(ex2)))
        scan_panel.set_status("Scan complete. %d headers tested." % total)
    except Exception as ex:
        scan_panel.set_status("Scan error: " + str(ex)); _log_err("_run_scan: "+str(ex))


class BurpExtender(IBurpExtender, ITab, IHttpListener, IProxyListener, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        global _CB, _HELPERS
        _CB=callbacks; _HELPERS=callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)
        _log_out("Version %s loading..." % EXT_VER)
        def _build():
            self._log_panel    = LogPanel()
            self._config_panel = ConfigPanel(self._log_panel)
            self._tabs = JTabbedPane()
            self._tabs.setBackground(C_BG); self._tabs.setForeground(C_FG)
            self._tabs.addTab("Configuration", self._config_panel)
            self._tabs.addTab("Injection Log",  self._log_panel)
        SwingUtilities.invokeAndWait(_build)
        callbacks.registerProxyListener(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)
        _log_out("Extension loaded. Configure the endpoint and enable interception.")

    def getTabCaption(self): return EXT_NAME
    def getUiComponent(self): return self._tabs

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest or not _STATE["enabled"]: return
        self._process(message.getMessageInfo())

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest or not _STATE["enabled"]: return
        if toolFlag == _CB.TOOL_PROXY: return       # proxy traffic handled by processProxyMessage
        if toolFlag != _CB.TOOL_REPEATER: return   # don't tamper with Scanner/Intruder traffic
        self._process(messageInfo)

    def createMenuItems(self, invocation):
        from javax.swing import JMenu
        msgs = invocation.getSelectedMessages()
        if not msgs or len(msgs)==0 or not msgs[0].getRequest(): return None
        msg_ref = msgs[0]
        menu = JMenu("SSRF Probe"); menu.setBackground(C_TB); menu.setForeground(C_FG)
        from java.awt.event import ActionListener as _MAL

        item_scan = JMenuItem("Individual Scan (1 header per request)")
        item_scan.setBackground(C_TB); item_scan.setForeground(C_FG)
        class _DoScan(_MAL):
            def actionPerformed(self2, e):
                try:
                    ep_val = _STATE.get("endpoint_value","").strip()
                    if not ep_val:
                        JOptionPane.showMessageDialog(None,"Configure the endpoint in the 'SSRF Probe' tab and click Save.","Endpoint not configured",JOptionPane.WARNING_MESSAGE); return
                    req_bytes = msg_ref.getRequest(); http_svc = msg_ref.getHttpService()
                    hdrs = list(_STATE.get("selected_headers",[]) or [])
                    if not hdrs: hdrs = [h for h in _SSRF_HEADERS if h.lower() != "host"]
                    from javax.swing import JFrame
                    sp = ScanPanel("SSRF-Scan")
                    frame = JFrame("SSRF Probe - Individual Scan  |  %s  |  %d headers" % (ep_val[:40], len(hdrs)))
                    frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE)
                    frame.setSize(1200,700); frame.getContentPane().add(sp)
                    frame.setLocationRelativeTo(None); frame.setVisible(True)
                    _t = threading.Thread(target=lambda: _run_scan(req_bytes,http_svc,hdrs,sp))
                    _t.start()
                except Exception as ex:
                    JOptionPane.showMessageDialog(None,"Error: "+str(ex),"Error",JOptionPane.ERROR_MESSAGE)
        item_scan.addActionListener(_DoScan())

        item_all = JMenuItem("Inject All at Once (Repeater)")
        item_all.setBackground(C_TB); item_all.setForeground(C_FG)
        class _DoAll(_MAL):
            def actionPerformed(self2, e):
                try:
                    if not _STATE.get("endpoint_value","").strip():
                        JOptionPane.showMessageDialog(None,"Configure the endpoint first.","Endpoint not configured",JOptionPane.WARNING_MESSAGE); return
                    req_bytes = msg_ref.getRequest(); http_svc = msg_ref.getHttpService()
                    modified  = _inject_request(req_bytes, http_svc)
                    if modified:
                        _CB.sendToRepeater(http_svc.getHost(),http_svc.getPort(),http_svc.getProtocol()=="https",modified,"SSRF-All")
                    else:
                        JOptionPane.showMessageDialog(None,"No payload injected. Check endpoint and headers.","Warning",JOptionPane.WARNING_MESSAGE)
                except Exception as ex:
                    JOptionPane.showMessageDialog(None,"Error: "+str(ex),"Error",JOptionPane.ERROR_MESSAGE)
        item_all.addActionListener(_DoAll())
        menu.add(item_scan); menu.add(item_all)
        from java.util import ArrayList
        result = ArrayList(); result.add(menu)
        return result

    def _process(self, messageInfo):
        try:
            http_service = messageInfo.getHttpService()
            request      = messageInfo.getRequest()
            if _STATE["scope_only"]:
                url = _HELPERS.analyzeRequest(http_service,request).getUrl()
                if not _CB.isInScope(url): return
            modified = _inject_request(request, http_service)
            if modified:
                messageInfo.setRequest(modified)
                SwingUtilities.invokeLater(self._log_panel.refresh)
        except Exception as ex:
            _log_err("processHttpMessage: " + str(ex))
