"""BUCKY lanes — proven tool-lanes from the live campaign, packaged.

Lane philosophy: only ship what we have ACTUALLY RUN and verified in the
field (181 operational cycles). Anything unverified is an experiment, not a lane.

- browse lane : firefox + geckodriver, headless ON THE KALI VM
  (chromium-150 zygote-crashes on this Kali image — do not downgrade).
- probe lane  : single-gentle-GET header/body inspector (curl).
- msgcap lane : embed a URL in a lab attacker-page and capture every
  cross-origin postMessage it fires (produced the P79 IFRAME_READY finding).

Every lane auto-archives evidence (screenshots, captures, bodies) under
``paths.evidence_root`` with timestamped names.
"""
from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import load_config
from .vmbridge import run, sync_down, sync_up, port_free, ensure_vm

_CFG = None


def _cfg():
    global _CFG
    if _CFG is None:
        _CFG = load_config()
    return _CFG


def _evid_dir() -> Path:
    p = Path(_cfg().paths.evidence_root)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------- browse lane
FORGE_BROWSE = r'''
import time, json
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
svc = Service(executable_path="/usr/bin/geckodriver")
opts = Options()
opts.add_argument("-headless")
drv = webdriver.Firefox(service=svc, options=opts)
out = {"ok": False}
try:
    drv.get("__URL__")
    time.sleep(__WAIT__)
    out["title"] = drv.title
    out["url_final"] = drv.current_url
    out["text"] = drv.execute_script(
        "return document.body ? document.body.innerText.slice(0, 4000) : ''")
    out["links"] = drv.execute_script(
        "return Array.from(document.links).slice(0, 60).map(a => a.href)")
    drv.save_screenshot("/tmp/forge-browse.png")
    out["ok"] = True
finally:
    drv.quit()
print("FORGE_BROWSE_JSON:" + json.dumps(out))
'''


def browse(url: str, wait_s: int = 20) -> dict[str, Any]:
    """Open URL in headless firefox ON THE KALI VM.

    Returns a result dict with title/final-url/body-text/links plus a local
    screenshot path under the evidence root. Gentle single-load by design.

    Args:
        url: target URL (must include scheme).
        wait_s: seconds to let SPA JS settle before extraction.

    Security: single load, no interaction, no credentials ever entered.
    """
    ensure_vm()
    script = FORGE_BROWSE.replace("__URL__", url).replace("__WAIT__", str(wait_s))
    stamp = _stamp()
    local_script = _evid_dir() / f"browse-{stamp}.py"
    local_script.write_text(script, encoding="utf-8")
    sync_up(str(local_script), "/tmp/forge-browse.py")
    r = run("python3 /tmp/forge-browse.py 2>&1", timeout=180)
    result: dict[str, Any] = {"ok": False, "raw": r.output}
    mstart = r.output.find("FORGE_BROWSE_JSON:")
    if mstart >= 0:
        tail = r.output[mstart + len("FORGE_BROWSE_JSON:"):]
        try:
            result, _ = json.JSONDecoder().raw_decode(tail)
        except json.JSONDecodeError:
            pass
    shot_local = _evid_dir() / f"browse-{stamp}.png"
    sync_down("/tmp/forge-browse.png", str(shot_local))
    if shot_local.exists():
        result["screenshot"] = str(shot_local)
    result["stamp"] = stamp
    return result


# ---------------------------------------------------------------- probe lane
def probe(url: str, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    """Gentle single-GET probe: status, headers, body-size, first bytes.

    Args:
        url: target URL.
        extra_headers: optional headers merged into the request
            (e.g. ``{"Origin": "https://evil.example"}`` for CORS reflection tests).
    """
    ensure_vm()
    hdr = ""
    if extra_headers:
        hdr = " ".join(f'-H "{k}: {v}"' for k, v in extra_headers.items())
    cmd = (
        f"curl -sk --max-time 25 {hdr} -o /tmp/forge-probe.body "
        f'-w "HTTP-STATUS:%{{http_code}}|SIZE:%{{size_download}}|TIME:%{{time_total}}\\n" '
        f"-D /tmp/forge-probe.headers '{url}'"
    )
    r = run(cmd, timeout=60)
    head = run("cat /tmp/forge-probe.headers 2>/dev/null | head -40", timeout=30)
    body_head = run("head -c 600 /tmp/forge-probe.body 2>/dev/null", timeout=30)
    status_line = next((l for l in r.output.splitlines()
                        if "HTTP-STATUS" in l), "")
    return {
        "ok": r.ok,
        "status_line": status_line,
        "headers": head.output,
        "body_head": body_head.output,
        "url": url,
    }


# ---------------------------------------------------------------- msgcap lane
FORGE_MSGCAP = r'''
import time, json, threading, http.server
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service

ATTACKER_PAGE = """
<!DOCTYPE html><html><body>
<iframe id="target" src="__URL__" style="width:900px;height:600px"></iframe>
<pre id="log"></pre><script>
window.__msgs = [];
window.addEventListener("message", (e) => {
  const d = e.data || {};
  const entry = {origin: e.origin, type: d.type || "?",
    keys: d.data ? Object.keys(d.data).slice(0, 15) : [],
    preview: JSON.stringify(d).slice(0, 400)};
  window.__msgs.push(entry);
  document.getElementById("log").textContent += JSON.stringify(entry) + "\\n";
});
</script></body></html>
"""

class Srv(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(ATTACKER_PAGE.encode())
    def log_message(self, *a): pass

srv = http.server.HTTPServer(("127.0.0.1", __PORT__), Srv)
threading.Thread(target=srv.serve_forever, daemon=True).start()

svc = Service(executable_path="/usr/bin/geckodriver")
opts = Options(); opts.add_argument("-headless")
drv = webdriver.Firefox(service=svc, options=opts)
out = {"ok": False, "messages": []}
try:
    drv.get("http://127.0.0.1:__PORT__/")
    time.sleep(__WAIT__)
    out["messages"] = drv.execute_script(
        "return JSON.parse(JSON.stringify(window.__msgs || []))")
    out["iframe_src"] = drv.execute_script(
        "const f = document.getElementById('target'); return f ? f.src : null;")
    drv.save_screenshot("/tmp/forge-msgcap.png")
    out["ok"] = True
finally:
    drv.quit()
    srv.shutdown()
print("FORGE_MSGCAP_JSON:" + json.dumps(out))
'''


def msg_capture(url: str, wait_s: int = 30, port: int = 19007) -> dict[str, Any]:
    """Embed ``url`` in a lab attacker-page on the VM and capture every
    cross-origin postMessage it fires at the parent.

    This is the lane that produced the P79 IFRAME_READY finding (a prod
    care-app handshakes with ANY parent origin). Observation only — nothing
    is sent to the embedded app beyond loading it.

    Args:
        url: target URL to embed in the lab iframe.
        wait_s: seconds to observe messages after embed.
        port: lab HTTP-server port on the VM (freed before use).

    Returns:
        dict with ``messages`` (origin/type/keys/preview each), ``iframe_src``,
        and ``screenshot`` path under the evidence root.
    """
    port_free([port])
    script = (FORGE_MSGCAP
              .replace("__URL__", url)
              .replace("__WAIT__", str(wait_s))
              .replace("__PORT__", str(port)))
    stamp = _stamp()
    local_script = _evid_dir() / f"msgcap-{stamp}.py"
    local_script.write_text(script, encoding="utf-8")
    sync_up(str(local_script), "/tmp/forge-msgcap.py")
    r = run("python3 /tmp/forge-msgcap.py 2>&1", timeout=240)
    result: dict[str, Any] = {"ok": False, "raw": r.output}
    mstart = r.output.find("FORGE_MSGCAP_JSON:")
    if mstart >= 0:
        tail = r.output[mstart + len("FORGE_MSGCAP_JSON:"):]
        try:
            result, _ = json.JSONDecoder().raw_decode(tail)
        except json.JSONDecodeError:
            pass
    shot_local = _evid_dir() / f"msgcap-{stamp}.png"
    sync_down("/tmp/forge-msgcap.png", str(shot_local))
    if shot_local.exists():
        result["screenshot"] = str(shot_local)
    result["stamp"] = stamp
    return result
