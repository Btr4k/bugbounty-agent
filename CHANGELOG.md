# Changelog

## v2.2.3

- Reject untouched placeholder API keys before a scan starts instead of
  reporting them as configured.
- Make the installer recognize an existing Arjun installation and use `pipx`
  on externally managed Python environments.
- Make AI request timeouts configurable and serialize Nuclei runs to reduce
  timeouts and peak memory use.
- Fall back to CertSpotter when crt.sh is unavailable.
- Remove the redundant build step from the automatic-install quick start.

## v2.2.2

- Continue reconnaissance and scanning when an optional external tool fails,
  while marking the assessment as partial.
- Apply `recon.timeout` only to passive reconnaissance sources so Katana and JS
  downloads do not inherit an expired context.
- Query crt.sh over IPv4 with shorter retries to avoid broken-IPv6 stalls.
- Include failed optional tools and reconnaissance completeness in reports.

## v2.2.1

- Add optional authenticated scanning with environment-backed headers and
  cookies protected by an explicit target-host allowlist.
- Redact configured credentials before findings reach AI providers or reports.
- Stop printing partial AI API keys in CLI output.
- Separate validation outcomes into confirmed, manual-review, and rejected.
- Include captured requests, evidence references, and missing evidence in
  reports.
- Add `--check-config` and release-archive compatibility smoke testing.

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
