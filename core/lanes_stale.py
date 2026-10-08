"""BUCKY lanes.stale — archived-asset resurrection detection.

Agent-I composition (novel — no precedent found in literature):
- Out of Sight [CCS'21]: Wayback CDX past-vs-current diffing (1,953
  orphaned pages on 907/100k domains, some 20 years old).
- Lauinger [NDSS'17]: 37% of 133k sites ship known-vulnerable library
  versions; update lag measured in YEARS — archived captures hold
  long-lived attack surface.

The inversion: keep .js URLs — archived bundle URLs that still return
200 but are unreferenced by the live page = prime stale-asset targets;
diff oldest-vs-newest captures for removed endpoints/schemes/allowlists.

Deterministic, stdlib-only. CDX fetch is a VM-side single GET (gentle).
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass

# resource extensions we DROPPED for pages; we KEEP these for assets
_ASSET_EXT = (".js", ".mjs", ".jsx")
_PAGE_EXT = (".html", ".htm", ".php", ".asp", ".aspx", ".jsp", "/")


@dataclass(frozen=True)
class StaleAsset:
    url: str
    first_seen: str   # earliest CDX timestamp
    last_seen: str    # latest CDX timestamp
    still_live: bool  # 200 on live fetch
    referenced_live: bool  # present in current page/script inventory
    risk: str         # why it matters


def cdx_query_url(domain: str, *, match_type: str = "domain") -> str:
    """Build the Wayback CDX API URL for one domain (no fetching)."""
    q = (f"http://web.archive.org/cdx/search/cdx"
         f"?url={urllib.parse.quote(domain)}"
         f"&matchType={match_type}&filter=statuscode:200"
         f"&collapse=urlkey&fl=timestamp,original&output=json")
    return q


def parse_cdx(cdx_json: str) -> list[tuple[str, str]]:
    """Parse CDX output rows -> [(timestamp, original_url)] sorted."""
    try:
        rows = json.loads(cdx_json)
    except (ValueError, TypeError):
        return []
    if not rows or not isinstance(rows, list):
        return []
    out: list[tuple[str, str]] = []
    for row in rows[1:]:  # header row dropped
        if isinstance(row, list) and len(row) >= 2:
            out.append((str(row[0]), str(row[1])))
    out.sort()
    return out


def classify_assets(rows: list[tuple[str, str]],
                    live_script_urls: set[str],
                    live_probe_ok: set[str]) -> list[StaleAsset]:
    """Classify archived rows into stale-asset risk classes.

    Args:
        rows: (timestamp, url) from parse_cdx.
        live_script_urls: script URLs referenced by the CURRENT page.
        live_probe_ok: archived URLs that still return 200 live.

    Risk classes:
      stale-still-live    — archived, 200 live, NOT referenced live
                            (removed from page but still served!)
      stale-referenced    — archived and still referenced (normal)
      gone                — archived, not live anymore (history only)
    """
    by_url: dict[str, list[str]] = {}
    for ts, url in rows:
        if not url.lower().endswith(_ASSET_EXT):
            continue
        by_url.setdefault(url, []).append(ts)
    out: list[StaleAsset] = []
    for url, stamps in sorted(by_url.items()):
        referenced = url in live_script_urls or any(
            u.endswith(url) or url.endswith(u) for u in live_script_urls)
        live_ok = url in live_probe_ok or any(
            u.endswith(url) or url.endswith(u) for u in live_probe_ok)
        if live_ok and not referenced:
            risk = "stale-still-live"
        elif live_ok and referenced:
            risk = "stale-referenced"
        else:
            risk = "gone"
        out.append(StaleAsset(url, stamps[0], stamps[-1], live_ok,
                               referenced, risk))
    return out


def diff_captures(old_text: str, new_text: str) -> dict[str, list[str]]:
    """Diff two captures of the SAME bundle: structures present in old
    but absent in new = removed surface; the inverse = newly added.

    Uses the jsdeep miners for structure extraction so the diff is at
    the semantic level (endpoints, schemes, tenants), not raw lines.
    """
    from core.lanes_jsdeep import mine_bundle, summarize
    old = summarize(mine_bundle(old_text))
    new = summarize(mine_bundle(new_text))
    removed: list[str] = []
    added: list[str] = []
    kinds = set(old) | set(new)
    for k in kinds:
        o, n = old.get(k, 0), new.get(k, 0)
        if o > n:
            removed.append(f"{k}: {o} -> {n}")
        elif n > o:
            added.append(f"{k}: {n} (was {o})")
    return {"removed": removed, "added": added}
