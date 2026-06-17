# Changelog

## v2.3.0

- **Removed the SQLi, FFUF, and Arjun modules.** In practice they produced no
  confirmed findings while consuming most of the scan budget: Arjun failed on
  every target, the nuclei-based SQLi pass was a redundant second nuclei run
  that was always OOM-killed, and FFUF added minutes for zero results without a
  wordlist. Their config sections and dependencies were dropped.
- **Active scanners now run sequentially (nuclei → dalfox), never in parallel.**
  Running several heavy scanners at once exhausted memory and the OOM killer
  terminated them mid-scan ("signal: killed"). One scanner at a time finishes
  reliably within budget.
- **Fixed nuclei reporting zero findings on slow targets.** The root cause was
  that a full ~1700-template sweep cannot finish on hosts that are
  slow/WAF-throttled, so the run was killed at the deadline before reaching the
  templates that match — and which findings surfaced first was essentially luck
  (one run found 3, the next found 0). Fixes:
  - **Cap the scan at the 25 highest-priority hosts** so the full template sweep
    actually completes within budget (clean exit = nothing lost), keeping the
    valuable names and dropping Certificate-Transparency noise.
  - **Capture results from both the `-o` file and stdout**, so partial findings
    survive a deadline stop regardless of how Nuclei buffers output.
  - **Treat a budget time-out as partial coverage, not a tool failure** — no more
    "❌ failed" when findings were captured; the report's Scan Coverage section
    states the coverage was time-boxed.
- Dropped the bulky low-signal `misconfig` tag (~800 templates, no confirmed
  findings here) and raised the default `rate_limit` to 150. Default nuclei
  budget is 20 minutes.
- **Stopped losing findings when AI validation is unavailable.** If the AI
  validator timed out or rate-limited, the whole batch of tool candidates was
  silently dropped (e.g. 6 candidates → only 1 in the report). Failed batches are
  now routed to **Manual Review** with their captured evidence intact, so every
  real candidate still reaches the report when the validator is degraded.
- **Improved reportability triage.** Protected diagnostic endpoints such as
  `Trace.axd` returning 401/403 are now rejected as not reportable, while exposed
  debug/profiling pages such as MiniProfiler/phpinfo/error logs are promoted to
  medium-value findings when the captured HTTP 200 response contains runtime,
  framework, SQL, or server-internal evidence.
- **Added coverage-quality scoring.** Reports now show Coverage Grade,
  parameterized URL counts, and negative-result confidence so a clean scan with
  shallow URL discovery is reported as limited coverage rather than proof of low
  risk.
- Made Katana much faster: shallow depth-1 crawl, 20 prioritized targets, and a
  4-minute cap (down from a depth-2 crawl that dominated runtime at 9+ minutes).
- **Richer, more professional reports.** Findings now include the AI-generated
  impact assessment, remediation, security context, description, CWE, and
  references — all previously discarded — plus a new Scan Coverage section.

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
