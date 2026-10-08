Lab CSP allows unsafe-inline and unsafe-eval (B1) on target endpoint

**CWE:** CWE-79

## Environment
Kali Linux 2026.2 VM (target 127.0.0.1:19077, BUCKY lab_serve.py), curl 8.x, Chrome-verified headers; environment locked in sealed transcript

## Steps to Reproduce
1. HUNT-E2E-LAB (scripted-policy; LLM slot awaits user key) | Expected: (as described in this step)
2. probe / -> B1 (B1: unsafe-inline/eval without nonce -> zero XSS mitigation) | Expected: B1 (B1: unsafe-inline/eval without nonce -> zero XSS mitigation)
3. probe /clean -> clean | Expected: clean
4. handler vuln=P1 clean=strict | Expected: (as described in this step)
5. secrets vuln=['aws-access-key', 'azure-client-secret', 'jwt'] clean=0 | Expected: (as described in this step)
6. FINISH: e2e hunt chain verified TP=B1 FP=0 in 4.8s | Expected: (as described in this step)
7. Expected: CSP header contains unsafe-inline and unsafe-eval

## PoC (machine-checkable)
```
curl -sI http://127.0.0.1:19077/ | grep -i content-security-policy
```

## Impact
The Content-Security-Policy on the target permits unsafe-inline and unsafe-eval with no nonce or strict-dynamic protection, which provides zero XSS mitigation: any injected inline script executes without CSP interference. An attacker who achieves a single HTML injection point can run arbitrary JavaScript in page origin, hijacking sessions and exfiltrating user data from the application.

## Suggested Remediation
See vendor guidance for the vulnerable class.

## Evidence (SHA-sealed)
- MANIFEST.json
- transcript.log

## References
- https://cheatsheetseries.owasp.org
-  CWE-79