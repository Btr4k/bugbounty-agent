# Changelog

## v2.2.6

- Feed all current Katana crawl URLs into parameter-based scanners when
  historical URL providers return no data.
- Run the primary Nuclei profile before the SQLi profile deterministically.
- Use a high-signal default Nuclei profile focused on exposures,
  misconfigurations, takeovers, and default credentials so the scan completes
  instead of timing out across every installed template.
- Report discovered URL and raw tool-candidate counts, with a prominent warning
  when an incomplete scan produces no candidates.

## v2.2.5

- Treat every unsuccessful Nuclei exit as a partial scan failure, even when
  Nuclei writes warnings or progress text to standard output.
- Preserve and report valid partial Nuclei and SQLi findings captured before a
  timeout or subprocess failure.
- Keep Nuclei's JSONL output channel free of unused progress statistics.
- Skip informational Nuclei templates by default because informational findings
  are intentionally excluded from analysis and reports.

## v2.2.4

- Reliably detect the ProjectDiscovery `httpx` binary when a Python `httpx`
  command shadows it on `PATH`.
- Allow enough time for `httpx -version` on slow networks and share the same
  resolver between preflight checks and the scanner.
- Do not fall back to blind active scanning when an enabled `httpx` probe
  fails or confirms no live hosts.
- Route AI-only JavaScript candidates to manual review and reserve automatic
  confirmation for deterministic, source-grounded secret patterns.
- Continue to partial report generation when an AI batch fails.
- Apply the configured thread and rate ceilings to Nuclei, SQLi, Httpx, and
  FFUF, with safer defaults for modest servers.
- Discover tools installed by Go and pipx even when their user-level binary
  directories are missing from the shell `PATH`.

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
