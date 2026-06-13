# Changelog

## v2.2.0

- Enforce target scope and exclusions across reconnaissance and scanning.
- Require machine-captured evidence and at least 0.85 confidence for reportable findings.
- Mark incomplete assessments as partial instead of implying the target is secure.
- Remove weak CORS and unused SQLMap scanners.
- Treat HTTPX, Arjun, Nmap, and vhost discovery as reconnaissance rather than vulnerabilities.
- Verify sensitive FFUF matches by response content.
- Ground JavaScript findings against downloaded source content.
- Add strict configuration validation, private report permissions, tests, CI, and Dependabot.
- Require Go 1.25 and update `golang.org/x/sys` to the patched release.
