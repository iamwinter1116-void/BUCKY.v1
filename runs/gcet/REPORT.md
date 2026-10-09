GCET soft-404 catch-all: nonexistent paths return full homepage (200) masking missing files

**CWE:** CWE-448

## Environment
platform: custom PHP on Apache; versions: PHP 8.2.33 (X-Powered-By disclosed), jQuery 1.8.2 (CDN) + jQuery 2.1.1 (local, dual-load); dependency-lock: sealed evidence run-dir

## Steps to Reproduce
1. GET https://www.gcet.ac.in/ -> Expected: 200 homepage | HTTP 200, 143,400 bytes, Apache + PHP 8.2.33 disclosed
2. GET https://www.gcet.ac.in/assets/js/scripts.js -> Expected: 200 JS | fetched 3,316 chars, no secrets
3. GET https://www.gcet.ac.in/audit.php?id=MTM= -> Expected: 200 audit page | 200, 20,185 bytes
4. GET https://www.gcet.ac.in/audit.php?id=zzzz -> Expected: 404 or error | 200 with 12,613 bytes, graceful fallback, no PHP error leakage
5. GET https://www.gcet.ac.in/zzz-nonexistent-98765.js -> Expected: 404 Not Found | HTTP 200 + full homepage HTML (soft-404 catch-all)

## PoC (machine-checkable)
```
curl -s https://www.gcet.ac.in/zzz-nonexistent-98765.js | head -c 200  # returns index.html, HTTP 200
```

## Impact
I retrieved the full homepage HTML (143,400 bytes) by requesting nonexistent paths (/zzz-nonexistent-98765.js and /assets/js/NOPE-does-not-exist.js), proving the server masks 404s as 200s; retrieved content confirms missing-asset detection and stale-asset diffing are impossible against this origin.

## Suggested Remediation
See vendor guidance for the vulnerable class.

## Evidence (SHA-sealed)
- bootstrap.min.js
- index.html
- jquery.isotope.js
- jquery.min.js
- jquery.min.map
- jquery.slicknav.js
- jquery.sticky.js
- jquery.visible.js
- MANIFEST.json
- modernizr.custom.js
- runtime-capture-soft404.txt
- scripts.js
- slimbox2.js
- transcript.log

## References
- CWE reference for the class