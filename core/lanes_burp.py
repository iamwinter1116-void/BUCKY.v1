"""BUCKY lanes.burp — Burp Suite proxy-capture lane (Community edition).

Honest capability check (verified live on the VM, Oct 2026):
- Burp 2026.7.2 Kali build has NO REST API flag (that is Burp Pro's
  Montoya REST extension, absent in community). We therefore integrate
  Burp the way it works in community: as an intercepting PROXY.
- Doctrine fit: our hunting is passive-first; Burp's value here is
  request/response capture + manual replay through its proxy, and its
  match-replace rules for deterministic A/B param-diffs.

This lane:
1. LAUNCH: burpsuite with a headless-compatible X (Xvfb) on the VM,
   listening proxy on 127.0.0.1:8080.
2. CAPTURE: our probe/browse lanes can route through the Burp proxy
   (urllib proxy handler) so every request lands in Burp's site-map.
3. EXPORT: Burp community can persist a project file; we seal it in the
   evidence dir like any other artifact (deterministic re-derivation
   via our own captured copies).
"""
from __future__ import annotations

import urllib.request
from dataclasses import dataclass

PROXY_ADDR = "127.0.0.1:8080"


@dataclass(frozen=True)
class ProxyLane:
    """A urllib opener routed through the Burp proxy."""
    proxy_url: str = f"http://{PROXY_ADDR}"

    def opener(self) -> urllib.request.OpenerDirector:
        return urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": self.proxy_url,
                                         "https": self.proxy_url}))

    def get(self, url: str, timeout: int = 15) -> tuple[int, str]:
        """One gentle GET through Burp (lands in its site-map)."""
        rq = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; bucky-burp-lane/0.7)"})
        try:
            with self.opener().open(rq, timeout=timeout) as r:
                return r.status, r.read(262144).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(262144).decode("utf-8", "replace")


def proxy_alive(vm_run) -> bool:
    """Check the Burp proxy port on the VM (vm_run = vmbridge.run)."""
    r = vm_run(f"curl -s -m 3 -o /dev/null -w '%{{http_code}}' "
               f"-x http://{PROXY_ADDR} http://127.0.0.1:19077/clean || true")
    # 000 = proxy not up; anything else means the proxy chain worked
    return r.ok and r.output.strip().endswith("200")


def launch_burp(vm_run, project_file: str = "~/bucky-lab/burp-project.burp") -> str:
    """Launch Burp with an Xvfb display on the VM (community-safe).

    Returns the command issued (for the transcript). The Burp UI opens on
    the VM screen; the operator can watch the site-map fill live — that is
    the point of the Burp lane: operator-visible proxy capture.
    """
    cmd = (f"nohup burpsuite --project-file={project_file} "
           f"--use-defaults --disable-auto-update "
           f">/tmp/burp-lane.log 2>&1 &")
    vm_run(cmd)
    return cmd
