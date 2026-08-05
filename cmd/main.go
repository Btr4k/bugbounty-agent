package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/analyzer"
	"github.com/Btr4k/bugbounty-agent/internal/config"
	"github.com/Btr4k/bugbounty-agent/internal/hunter"
	"github.com/Btr4k/bugbounty-agent/internal/logger"
	"github.com/Btr4k/bugbounty-agent/internal/recon"
	"github.com/Btr4k/bugbounty-agent/internal/redaction"
	"github.com/Btr4k/bugbounty-agent/internal/reporter"
	"github.com/Btr4k/bugbounty-agent/internal/scanner"
	"github.com/Btr4k/bugbounty-agent/internal/scope"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const appVersion = "2.3.0"

var (
	cfgFile      string
	targetDomain string
	outputDir    string
	verbose      bool
	aiProvider   string
	aiModel      string
	skipRecon    bool
	skipScan     bool
	jsOnly       bool
	checkConfig  bool
	includeSubs  bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:           "hawkeye",
		Short:         "HawkEye - AI-Powered Bug Bounty Hunting Tool",
		Long:          banner(),
		Version:       appVersion,
		Args:          cobra.NoArgs,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE:          runAgent,
	}

	rootCmd.Flags().StringVarP(&cfgFile, "config", "c", "config.yaml", "Config file")
	rootCmd.Flags().StringVarP(&targetDomain, "target", "t", "", "Target domain")
	rootCmd.Flags().StringVarP(&targetDomain, "domain", "d", "", "Target domain (alias for -t/--target)")
	rootCmd.Flags().StringVarP(&outputDir, "output", "o", "./reports", "Output directory")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.Flags().StringVar(&aiProvider, "ai-provider", "", "AI provider override: auto, claude, deepseek, openai, openrouter (configure custom endpoints in YAML)")
	rootCmd.Flags().StringVar(&aiModel, "ai-model", "", "AI model name (e.g. deepseek-v4-flash, gpt-4o-mini, claude-sonnet-5)")
	rootCmd.Flags().BoolVar(&skipRecon, "skip-recon", false, "Skip the reconnaissance phase")
	rootCmd.Flags().BoolVar(&skipScan, "skip-scan", false, "Skip the vulnerability scanning phase")
	rootCmd.Flags().BoolVar(&jsOnly, "js-only", false, "Run JS file analysis only (skips vulnerability scanning)")
	rootCmd.Flags().BoolVar(&checkConfig, "check-config", false, "Validate the config file and exit")
	rootCmd.Flags().BoolVar(&includeSubs, "include-subdomains", false, "Explicitly authorize discovered subdomains of the target")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", terminalSafe(err.Error()))
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) error {
	printBanner()

	if checkConfig {
		if _, err := config.LoadWithAIOverrides(cfgFile, aiProvider, aiModel); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		fmt.Printf("Configuration is valid and compatible with HawkEye v%s\n", appVersion)
		return nil
	}

	// Validate that at least -t/--target or -d/--domain was provided
	if targetDomain == "" {
		return fmt.Errorf("target domain is required: use -t <domain> or -d <domain>")
	}

	// Initialize logger
	log := logger.New(verbose)
	defer log.Close()

	// Load config
	cfg, err := config.LoadWithAIOverrides(cfgFile, aiProvider, aiModel)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Validate target domain (prevent command injection)
	if err := validateDomain(targetDomain); err != nil {
		return fmt.Errorf("invalid target domain: %w", err)
	}

	// Add target authorization before planning required tools. A wildcard rule
	// alone excludes the apex; the CLI flag intentionally authorizes both.
	cfg.Target.Domains = configuredTargetRules(targetDomain, includeSubs)
	cfg.Reporting.OutputDir = outputDir
	targetPolicy := scope.New(cfg.Target)
	if err := targetPolicy.ValidationError(); err != nil {
		return fmt.Errorf("invalid target scope: %w", err)
	}
	if !targetPolicy.AllowsHost(targetDomain) {
		return fmt.Errorf("target %q is excluded or outside the configured scope", targetDomain)
	}
	if jsOnly && (skipRecon || !cfg.Recon.Enabled) {
		return fmt.Errorf("--js-only requires reconnaissance to discover JavaScript files")
	}
	if jsOnly && !cfg.Analysis.JSAnalysis {
		return fmt.Errorf("--js-only requires analysis.js_analysis to be enabled")
	}

	// Validate required tools are installed before wasting time
	ensureToolBinsOnPath()
	if err := checkTools(cfg, log); err != nil {
		return err
	}

	// Setup context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Warn("Received interrupt signal, shutting down...")
		cancel()
	}()

	startTime := time.Now()

	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.FgHiBlack)

	// Target info
	fmt.Println()
	white.Printf("  🎯 Target: ")
	cyan.Printf("%s\n", targetDomain)
	dim.Printf("  ⏰ Started: %s\n", startTime.Format("2006-01-02 15:04:05"))
	fmt.Println()

	// AI Provider info
	white.Printf("  🤖 AI Provider: ")
	cyan.Printf("%s\n", terminalConfigSafe(cfg, strings.ToUpper(cfg.AI.Provider)))
	white.Printf("  📦 AI Model:    ")
	cyan.Printf("%s\n", terminalConfigSafe(cfg, cfg.AI.Model))
	white.Printf("  🔑 API Key:     ")
	dim.Printf("[configured]\n")
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 1: Reconnaissance
	// ═══════════════════════════════════════
	var reconResults *recon.Results
	phaseStart := time.Now()

	if skipRecon || !cfg.Recon.Enabled {
		dim.Println("  ⏭️  Skipping reconnaissance phase (--skip-recon)")
		reconResults = &recon.Results{
			Subdomains: []string{targetDomain},
			URLs:       make([]string, 0),
			Endpoints:  make([]string, 0),
			IPs:        make([]string, 0),
			JSFiles:    make([]recon.JSFile, 0),
			Complete:   false,
		}
		fmt.Println()
	} else {
		printPhaseHeader("1", "RECONNAISSANCE", "📡")
		phaseStart = time.Now()

		reconEngine := recon.NewEngine(cfg, log)
		var err2 error
		reconResults, err2 = reconEngine.Run(ctx)
		if err2 != nil {
			return fmt.Errorf("reconnaissance failed: %w", err2)
		}

		reconDuration := time.Since(phaseStart)
		if reconResults.Complete {
			green.Printf("  ✅ Completed in %s\n", reconDuration.Round(time.Second))
		} else {
			yellow.Printf("  ⚠️  Completed partially in %s (failed: %s)\n",
				reconDuration.Round(time.Second), strings.Join(reconResults.FailedTools, ", "))
		}
		fmt.Printf("  ├── 🌐 Subdomains: %s\n", white.Sprintf("%d", len(reconResults.Subdomains)))
		fmt.Printf("  ├── 🔗 URLs:       %s\n", white.Sprintf("%d", len(reconResults.URLs)))
		fmt.Printf("  ├── 📍 Endpoints:  %s\n", white.Sprintf("%d", len(reconResults.Endpoints)))
		fmt.Printf("  └── 📜 JS Files:   %s\n", white.Sprintf("%d", len(reconResults.JSFiles)))

		// Print found subdomains if verbose
		if verbose && len(reconResults.Subdomains) > 0 {
			fmt.Println()
			yellow.Println("  📋 Sample Subdomains:")
			limit := 15
			if len(reconResults.Subdomains) < limit {
				limit = len(reconResults.Subdomains)
			}
			for i := 0; i < limit; i++ {
				dim.Printf("     %2d. ", i+1)
				fmt.Printf("%s\n", terminalConfigSafe(cfg, reconResults.Subdomains[i]))
			}
			if len(reconResults.Subdomains) > limit {
				dim.Printf("     ... and %d more\n", len(reconResults.Subdomains)-limit)
			}
		}
		fmt.Println()
	}

	// ═══════════════════════════════════════
	// Phase 2: Vulnerability Scanning
	// ═══════════════════════════════════════
	var scanResults *scanner.Results
	var critical, high, medium, low, info int
	var displayFindings []scanner.Finding

	if skipScan || jsOnly || !cfg.Scanning.Enabled {
		if jsOnly {
			dim.Println("  ⏭️  Skipping vulnerability scanning (--js-only: recon done, JS analysis next)")
		} else {
			dim.Println("  ⏭️  Skipping vulnerability scanning (--skip-scan)")
		}
		scanResults = &scanner.Results{
			Findings: make([]scanner.Finding, 0),
			Complete: false,
		}
		fmt.Println()
	} else {
		printPhaseHeader("2", "VULNERABILITY SCANNING", "🔍")
		cyan.Println("  🎯 Executing deep vulnerability scan with multiple tools")
		yellow.Println("  ⏳ This phase may take several minutes - please be patient")
		phaseStart = time.Now()

		scanEngine := scanner.NewEngine(cfg, log)
		var err2 error
		scanResults, err2 = scanEngine.Run(ctx, reconResults)
		if err2 != nil {
			return fmt.Errorf("scanning failed: %w", err2)
		}

		scanDuration := time.Since(phaseStart)
		critical, high, medium, low, info = countBySeverity(scanResults.Findings)

		// Filter findings for display (hide "info" severity)
		for _, f := range scanResults.Findings {
			if f.Severity != "info" {
				displayFindings = append(displayFindings, f)
			}
		}

		if scanResults.Complete {
			green.Printf("  ✅ Scan completed successfully in %s\n", scanDuration.Round(time.Second))
		} else if len(scanResults.FailedTools) > 0 {
			yellow.Printf("  ⚠️  Scan completed partially in %s (failed: %s)\n",
				scanDuration.Round(time.Second), strings.Join(scanResults.FailedTools, ", "))
		} else {
			yellow.Printf("  ⚠️  Scan completed in %s with partial coverage (time-boxed — not every host fully scanned)\n",
				scanDuration.Round(time.Second))
		}
		white.Printf("  📊 Scanner candidates awaiting validation: ")
		cyan.Printf("%d candidates (low/medium/high/critical)\n", len(displayFindings))
		if info > 0 {
			dim.Printf("  ℹ️  %d informational findings hidden from display\n", info)
		}
	}
	fmt.Println()

	// Show findings details (only actionable ones)
	if len(displayFindings) > 0 {
		white.Println("  ┌─────────────────────────────────────────────┐")
		white.Printf("  │")
		cyan.Printf("  📊 Candidate Severity Distribution")
		fmt.Print("       ")
		white.Println("│")
		white.Println("  ├─────────────────────────────────────────────┤")
		if critical > 0 {
			white.Printf("  │  ")
			red.Printf("🔴 CRITICAL")
			fmt.Printf("  → ")
			red.Printf("%-3d", critical)
			fmt.Print(" candidates              ")
			white.Println("│")
		}
		if high > 0 {
			white.Printf("  │  ")
			color.New(color.FgHiRed).Printf("🟠 HIGH")
			fmt.Printf("      → ")
			color.New(color.FgHiRed).Printf("%-3d", high)
			fmt.Print(" candidates              ")
			white.Println("│")
		}
		if medium > 0 {
			white.Printf("  │  ")
			yellow.Printf("🟡 MEDIUM")
			fmt.Printf("    → ")
			yellow.Printf("%-3d", medium)
			fmt.Print(" candidates              ")
			white.Println("│")
		}
		if low > 0 {
			white.Printf("  │  ")
			green.Printf("🟢 LOW")
			fmt.Printf("       → ")
			green.Printf("%-3d", low)
			fmt.Print(" candidates              ")
			white.Println("│")
		}
		white.Println("  └─────────────────────────────────────────────┘")

		// Print individual findings (only actionable ones)
		fmt.Println()
		white.Printf("  ")
		cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		white.Printf("  ")
		yellow.Println("🔍 UNVALIDATED SCANNER CANDIDATES (NOT CONFIRMED)")
		white.Printf("  ")
		cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
		fmt.Println()
		for i, f := range displayFindings {
			sevColor := dim
			sevIcon := "ℹ️ "
			sevLabel := "INFO"
			switch f.Severity {
			case "critical":
				sevColor = red
				sevIcon = "🔴"
				sevLabel = "CRITICAL"
			case "high":
				sevColor = color.New(color.FgHiRed)
				sevIcon = "🟠"
				sevLabel = "HIGH"
			case "medium":
				sevColor = yellow
				sevIcon = "🟡"
				sevLabel = "MEDIUM"
			case "low":
				sevColor = green
				sevIcon = "🟢"
				sevLabel = "LOW"
			}

			white.Printf("  [%d/%d] ", i+1, len(displayFindings))
			sevColor.Printf("%s %s", sevIcon, sevLabel)
			fmt.Println()
			white.Printf("  └─ ")
			cyan.Printf("Title: ")
			white.Printf("%s\n", terminalConfigSafe(cfg, f.Title))
			if f.Target != "" {
				white.Printf("     ")
				cyan.Printf("Target: ")
				dim.Printf("%s\n", terminalConfigSafe(cfg, f.Target))
			}
			if f.URL != "" {
				white.Printf("     ")
				cyan.Printf("URL: ")
				dim.Printf("%s\n", terminalConfigSafe(cfg, f.URL))
			}
			if f.Evidence != "" {
				white.Printf("     ")
				cyan.Printf("Evidence: ")
				dim.Printf("%s\n", evidenceSummary(f.Evidence))
			}
			if f.CVE != "" {
				white.Printf("     ")
				red.Printf("CVE: %s", terminalConfigSafe(cfg, f.CVE))
				fmt.Println()
			}
			if i < len(displayFindings)-1 {
				fmt.Println()
			}
		}
		fmt.Println()
		// Informational candidates stay out of the noisy terminal list. The
		// analyzer still adjudicates non-inventory info candidates; explicit port
		// inventory is retained as a rejected/non-vulnerability observation.
		if info > 0 {
			dim.Printf("  💡 Note: %d informational findings were hidden from display\n", info)
			dim.Println("     (They remain accounted for by the validation/reporting pipeline)")
			fmt.Println()
		}
		white.Printf("  ")
		cyan.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	}
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 2.5: JS File Analysis (Regex + AI)
	// ═══════════════════════════════════════
	if cfg.Analysis.JSAnalysis && len(reconResults.JSFiles) > 0 {
		printPhaseHeader("2.5", "JS FILE ANALYSIS (REGEX + AI)", "📜")
		phaseStart = time.Now()

		// Convert recon.JSFile to analyzer-compatible struct
		jsInput := make([]struct {
			URL     string
			Content string
			Size    int
			Source  string
		}, len(reconResults.JSFiles))
		for i, js := range reconResults.JSFiles {
			jsInput[i] = struct {
				URL     string
				Content string
				Size    int
				Source  string
			}{
				URL:     js.URL,
				Content: js.Content,
				Size:    js.Size,
				Source:  js.Source,
			}
		}

		// ── Step 1: Fast regex pre-scan (instant, no API calls) ──
		cyan.Printf("  🔎 Regex pre-scan on %d JS files...\n", len(reconResults.JSFiles))
		regexFindings := analyzer.ScanJSWithRegex(jsInput)
		if len(regexFindings) > 0 {
			green.Printf("  ├── ✅ Regex: found %d patterns\n", len(regexFindings))
			for _, rf := range regexFindings {
				sevColor := dim
				sevIcon := "ℹ️ "
				switch rf.Severity {
				case "critical":
					sevColor = red
					sevIcon = "🔴"
				case "high":
					sevColor = color.New(color.FgHiRed)
					sevIcon = "🟠"
				case "medium":
					sevColor = yellow
					sevIcon = "🟡"
				case "low":
					sevColor = green
					sevIcon = "🟢"
				}
				sevColor.Printf("     %s [%s] ", sevIcon, strings.ToUpper(rf.Severity))
				white.Printf("%s\n", terminalConfigSafe(cfg, rf.Title))
				if rf.Evidence != "" {
					dim.Printf("        Evidence: %s\n", evidenceSummary(rf.Evidence))
				}
			}
		} else {
			dim.Println("  ├── 🔎 Regex: no patterns detected")
		}

		// ── Step 2: AI-powered deep analysis ──
		cyan.Printf("  📁 AI analyzing %d JS files with %s...\n", len(reconResults.JSFiles), strings.ToUpper(cfg.AI.Provider))

		jsAnalyzer := analyzer.NewEngine(cfg, log)
		aiFindings, err := jsAnalyzer.AnalyzeJSFiles(ctx, jsInput)
		if err != nil {
			yellow.Printf("  ⚠️  JS AI analysis completed partially: %s\n", terminalConfigSafe(cfg, err.Error()))
			scanResults.Complete = false
			scanResults.FailedTools = append(scanResults.FailedTools, "ai-js-analysis")
		}

		// Locally detected values are masked before leaving the regex scanner, so
		// downstream deduplication must never compare redaction markers as if they
		// were the underlying secrets. Each detector already deduplicates against
		// raw values while those values are still local; merge only safe records.
		allJSFindings := append([]scanner.Finding(nil), regexFindings...)
		allJSFindings = append(allJSFindings, aiFindings...)

		jsDuration := time.Since(phaseStart)
		if err == nil {
			green.Printf("  ✅ Completed in %s\n", jsDuration.Round(time.Second))
		}

		if len(allJSFindings) > 0 {
			fmt.Printf("  └── 🔍 JS Findings: %s (Regex: %d, AI: %d)\n",
				white.Sprintf("%d", len(allJSFindings)),
				len(regexFindings), len(aiFindings))
			fmt.Println()
			yellow.Println("  📋 JS Analysis Results:")
			for _, jf := range allJSFindings {
				sevColor := dim
				sevIcon := "ℹ️ "
				switch jf.Severity {
				case "critical":
					sevColor = red
					sevIcon = "🔴"
				case "high":
					sevColor = color.New(color.FgHiRed)
					sevIcon = "🟠"
				case "medium":
					sevColor = yellow
					sevIcon = "🟡"
				case "low":
					sevColor = green
					sevIcon = "🟢"
				}
				sevColor.Printf("     %s [%s] ", sevIcon, strings.ToUpper(jf.Severity))
				white.Printf("%s\n", terminalConfigSafe(cfg, jf.Title))
				if jf.Evidence != "" {
					dim.Printf("        Evidence: %s\n", evidenceSummary(jf.Evidence))
				}
				if jf.Description != "" {
					dim.Printf("        Info:  %s\n", terminalConfigSafe(cfg, jf.Description))
				}
			}

			// Merge JS findings into scan results
			scanResults.Findings = append(scanResults.Findings, allJSFindings...)
			critical, high, medium, low, info = countBySeverity(scanResults.Findings)
		} else {
			dim.Println("  └── No sensitive data found in JS files")
		}
	} else if len(reconResults.JSFiles) == 0 {
		dim.Println("  ⏭️  JS Analysis: no JS files found during recon")
	}
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 3: AI Analysis
	// ═══════════════════════════════════════
	// Phase 2.7: AI Attack-Surface Hunter (hypotheses only — no requests sent)
	// ═══════════════════════════════════════
	if cfg.Hunter.Enabled && !jsOnly && reconResults != nil {
		printPhaseHeader("2.7", "AI ATTACK-SURFACE HUNTER", "🧠")
		phaseStart = time.Now()

		hunterEngine := hunter.NewEngine(cfg, log)
		hyps, herr := hunterEngine.Generate(ctx, reconResults)
		if herr != nil {
			yellow.Printf("  ⚠️  Hunter skipped: %s\n", terminalConfigSafe(cfg, herr.Error()))
		} else {
			green.Printf("  ✅ Completed in %s\n", time.Since(phaseStart).Round(time.Second))
			var observed, inferred []hunter.Hypothesis
			for _, h := range hyps {
				if h.Grounding == "observed" {
					observed = append(observed, h)
				} else {
					inferred = append(inferred, h)
				}
			}
			fmt.Printf("  └── 🧠 Attack hypotheses: %s total  (🔬 %s observed · 💭 %s inferred)\n",
				white.Sprintf("%d", len(hyps)), white.Sprintf("%d", len(observed)), white.Sprintf("%d", len(inferred)))
			if len(hyps) > 0 {
				printLead := func(n int, h hunter.Hypothesis) {
					dim.Printf("     %2d. ", n)
					fmt.Printf("[%s/%s] %s",
						terminalConfigSafe(cfg, strings.ToUpper(h.Severity)),
						terminalConfigSafe(cfg, h.Class),
						terminalConfigSafe(cfg, h.Target))
					if h.Parameter != "" {
						fmt.Printf("  (param: %s)", terminalConfigSafe(cfg, h.Parameter))
					}
					fmt.Printf("  — conf %.2f\n", h.Confidence)
				}
				if len(observed) > 0 {
					fmt.Println()
					green.Println("  🔬 Grounded leads (parameter/path seen in recon — verify manually):")
					for i, h := range observed {
						if i >= 10 {
							break
						}
						printLead(i+1, h)
					}
				}
				if len(inferred) > 0 {
					fmt.Println()
					yellow.Println("  💭 Inferred leads (guessed from naming — confirm the endpoint EXISTS first):")
					for i, h := range inferred {
						if i >= 10 {
							break
						}
						printLead(i+1, h)
					}
				}
				if path, werr := saveHypotheses(cfg.Reporting.OutputDir, targetDomain, hyps); werr != nil {
					yellow.Printf("  ⚠️  Could not save hypotheses file: %s\n", terminalConfigSafe(cfg, werr.Error()))
				} else {
					fmt.Printf("  └── 📄 Hypotheses: %s\n", cyan.Sprintf("%s", terminalConfigSafe(cfg, path)))
				}
			}
		}
		fmt.Println()
	}

	// ═══════════════════════════════════════
	printPhaseHeader("3", "AI-POWERED ANALYSIS", "🤖")
	phaseStart = time.Now()

	analyzerEngine := analyzer.NewEngine(cfg, log)
	analysisResults, err := analyzerEngine.Analyze(ctx, scanResults)
	if err != nil {
		yellow.Printf("  ⚠️  Validation pipeline completed partially: %s\n", terminalConfigSafe(cfg, err.Error()))
		scanResults.Complete = false
		scanResults.FailedTools = append(scanResults.FailedTools, "ai-validation")
	}

	analysisDuration := time.Since(phaseStart)
	if err == nil {
		green.Printf("  ✅ Completed in %s\n", analysisDuration.Round(time.Second))
	}
	fmt.Printf("  ├── ✓ Confirmed by evidence gates: %s\n", white.Sprintf("%d", countConfirmedFindings(analysisResults)))
	fmt.Printf("  ├── ? Manual review required: %s\n", white.Sprintf("%d", len(analysisResults.ManualReview)))
	fmt.Printf("  └── ✗ Rejected candidates: %s\n", white.Sprintf("%d", len(analysisResults.FalsePositives)))
	fmt.Println()

	// ═══════════════════════════════════════
	// Phase 4: Reporting
	// ═══════════════════════════════════════
	printPhaseHeader("4", "REPORT GENERATION", "📝")
	phaseStart = time.Now()

	reportGen := reporter.NewGenerator(cfg, log)
	reportPath, err := reportGen.Generate(reconResults, scanResults, analysisResults)
	if err != nil {
		return fmt.Errorf("report generation failed: %w", err)
	}

	reportDuration := time.Since(phaseStart)
	green.Printf("  ✅ Completed in %s\n", reportDuration.Round(time.Second))
	fmt.Printf("  └── 📄 Report: %s\n", cyan.Sprintf("%s", terminalConfigSafe(cfg, reportPath)))
	fmt.Println()

	duration := time.Since(startTime)

	// Print final summary
	printSummary(duration, reportPath, len(reconResults.Subdomains),
		len(scanResults.Findings), analysisResults,
		supportsNegativeConclusion(reconResults, scanResults, analysisResults))

	return nil
}

func configuredTargetRules(domain string, includeSubdomains bool) []string {
	if includeSubdomains {
		return []string{domain, "*." + domain}
	}
	return []string{domain}
}

func saveHypotheses(outputDir, target string, hyps []hunter.Hypothesis) (string, error) {
	if outputDir == "" {
		outputDir = "./reports"
	}
	if err := reporter.EnsurePrivateDirectory(outputDir); err != nil {
		return "", err
	}
	safe := regexp.MustCompile(`[^a-zA-Z0-9._-]+`).ReplaceAllString(target, "_")
	path := filepath.Join(outputDir, fmt.Sprintf("hypotheses-%s-%s.json", safe, time.Now().UTC().Format("20060102-150405.000000000")))
	data, err := json.MarshalIndent(hyps, "", "  ")
	if err != nil {
		return "", err
	}
	if err := reporter.WritePrivateFileAtomic(path, data); err != nil {
		return "", err
	}
	return path, nil
}

// evidenceSummary keeps all raw evidence out of terminal/CI logs. The shared
// redactor is still run so recognized credential metadata can be counted
// without exposing the captured value or creating hashes for low-entropy data.
func evidenceSummary(value string) string {
	result := redaction.MaskWithMetadata(value)
	if len(result.Matches) == 0 {
		return "[captured; withheld from terminal]"
	}
	return fmt.Sprintf("[captured; withheld from terminal; credentials-redacted:%d]", len(result.Matches))
}

// terminalSafe prevents tool/model-controlled text from injecting terminal
// control sequences or exposing recognized credentials.
func terminalSafe(value string) string {
	return redaction.Mask(redaction.SanitizeURLsInText(value))
}

// terminalConfigSafe additionally removes secrets explicitly configured by
// the operator, including opaque values that cannot be recognized by format.
func terminalConfigSafe(cfg *config.Config, value string) string {
	if cfg != nil {
		value = cfg.Redact(value)
	}
	return terminalSafe(value)
}

func ensureToolBinsOnPath() {
	existing := strings.Split(os.Getenv("PATH"), string(os.PathListSeparator))
	seen := make(map[string]bool, len(existing)+4)
	paths := make([]string, 0, len(existing)+4)
	home, _ := os.UserHomeDir()
	candidates := []string{os.Getenv("GOBIN")}
	if goPath := os.Getenv("GOPATH"); goPath != "" {
		candidates = append(candidates, filepath.Join(goPath, "bin"))
	}
	candidates = append(candidates,
		filepath.Join(home, "go", "bin"),
		filepath.Join(home, ".local", "bin"),
	)
	for _, candidate := range candidates {
		if candidate != "" && !seen[candidate] {
			seen[candidate] = true
			paths = append(paths, candidate)
		}
	}
	for _, path := range existing {
		if path != "" && !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	_ = os.Setenv("PATH", strings.Join(paths, string(os.PathListSeparator)))
}

func targetAuthorizesSubdomains(domains []string) bool {
	for _, domain := range domains {
		if strings.HasPrefix(strings.TrimSpace(domain), "*.") {
			return true
		}
	}
	return false
}

// checkTools validates that critical external tools are installed before scanning starts.
// Logs warnings for optional tools and fatals for required ones.
func checkTools(cfg *config.Config, log interface{ Infof(string, ...interface{}) }) error {
	type tool struct {
		name    string
		enabled bool
		install string
	}
	runRecon := cfg.Recon.Enabled && !skipRecon
	runScan := cfg.Scanning.Enabled && !skipScan && !jsOnly
	discoverSubdomains := targetAuthorizesSubdomains(cfg.Target.Domains)
	tools := []tool{
		{"subfinder", runRecon && discoverSubdomains && cfg.Recon.Tools.Subfinder, "./install.sh"},
		{"assetfinder", runRecon && discoverSubdomains && cfg.Recon.Tools.Assetfinder, "./install.sh"},
		{"waybackurls", runRecon && cfg.Recon.Tools.Wayback, "./install.sh"},
		{"katana", runRecon && cfg.Recon.Tools.Katana, "./install.sh"},
		{"httpx", runScan && cfg.Scanning.Tools.Httpx.Enabled, "./install.sh"},
		{"nuclei", runScan && cfg.Scanning.Tools.Nuclei.Enabled, "./install.sh"},
		{"dalfox", runScan && cfg.Scanning.Tools.Dalfox.Enabled, "./install.sh"},
		{"nmap", runScan && cfg.Scanning.Tools.Nmap.Enabled, "apt install nmap"},
	}

	missing := []string{}
	for _, t := range tools {
		if !t.enabled {
			continue
		}
		if !toolAvailable(t.name) {
			missing = append(missing, fmt.Sprintf("%s (install: %s)", t.name, t.install))
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("enabled tools are missing: %s", strings.Join(missing, "; "))
	}
	log.Infof("Preflight passed: all enabled external tools are available")
	return nil
}

func toolAvailable(name string) bool {
	if name != "httpx" {
		_, err := exec.LookPath(name)
		return err == nil
	}
	_, ok := scanner.ResolveHttpxBinary()
	return ok
}

// validateDomain checks that the domain only contains valid characters
// to prevent command injection via user-supplied input passed to exec.Command
var domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,251}[a-zA-Z0-9])?$`)

func validateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain cannot be empty")
	}
	if len(domain) > 253 {
		return fmt.Errorf("domain too long (max 253 characters)")
	}
	if !domainRegex.MatchString(domain) {
		return fmt.Errorf("domain contains invalid characters — only alphanumeric, dots and hyphens allowed")
	}
	// Prevent localhost/internal targets accidentally
	lowered := strings.ToLower(domain)
	blocked := []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"}
	for _, b := range blocked {
		if lowered == b {
			return fmt.Errorf("target '%s' is not a valid external domain", domain)
		}
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("domain contains an invalid DNS label")
		}
	}
	if _, err := scope.NewWithMode(config.TargetConfig{Domains: []string{domain}}, scope.ModeExact); err != nil {
		return err
	}
	return nil
}

func countBySeverity(findings []scanner.Finding) (int, int, int, int, int) {
	var critical, high, medium, low, info int
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		case "info":
			info++
		}
	}
	return critical, high, medium, low, info
}

func printPhaseHeader(num, title, icon string) {
	c := color.New(color.FgCyan, color.Bold)
	c.Printf("  ╔══════════════════════════════════════════════╗\n")
	c.Printf("  ║  %s Phase %s: %-32s║\n", icon, num, title)
	c.Printf("  ╚══════════════════════════════════════════════╝\n")
}

func printBanner() {
	banner := fmt.Sprintf(`
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                              ┃
┃   ██╗  ██╗ █████╗ ██╗    ██╗██╗  ██╗███████╗██╗   ██╗███████╗
┃   ██║  ██║██╔══██╗██║    ██║██║ ██╔╝██╔════╝╚██╗ ██╔╝██╔════╝
┃   ███████║███████║██║ █╗ ██║█████╔╝ █████╗   ╚████╔╝ █████╗
┃   ██╔══██║██╔══██║██║███╗██║██╔═██╗ ██╔══╝    ╚██╔╝  ██╔══╝
┃   ██║  ██║██║  ██║╚███╔███╔╝██║  ██╗███████╗   ██║   ███████╗
┃   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝
┃                                                              ┃
┃           AI-Powered Bug Bounty Hunting Tool v%-13s┃
┃            Multi-AI Engine | Nuclei | Deep Scan              ┃
┃                                                              ┃
┃                    Developed by @A_cyb3r                     ┃
┃                https://twitter.com/A_cyb3r                   ┃
┃                                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
`, appVersion)
	fmt.Println(color.CyanString(banner))
}

func banner() string {
	return `
╔══════════════════════════════════════════════════════════╗
║     HawkEye - AI Bug Bounty Hunter by @A_cyb3r          ║
║     Automated Security Testing & Vulnerability Analysis  ║
╚══════════════════════════════════════════════════════════╝
`
}

type summaryClassification string

const (
	summaryInconclusive summaryClassification = "inconclusive"
	summaryNoConfirmed  summaryClassification = "no-confirmed"
	summaryCritical     summaryClassification = "critical"
	summaryHigh         summaryClassification = "high"
	summaryMedium       summaryClassification = "medium"
	summaryLow          summaryClassification = "low"
)

type confirmedSeverityCounts struct {
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

func countConfirmedFindings(analysis *analyzer.Analysis) int {
	if analysis == nil {
		return 0
	}
	count := 0
	for _, finding := range analysis.ValidatedFindings {
		if finding.IsValid && strings.EqualFold(finding.Decision, "confirmed") {
			count++
		}
	}
	return count
}

func (c confirmedSeverityCounts) total() int {
	return c.Critical + c.High + c.Medium + c.Low + c.Info
}

// classifySummary only considers findings that passed the analyzer's evidence
// gates. Raw scanner candidates, manual-review items, and rejected candidates
// must never drive an urgent final classification.
func classifySummary(analysis *analyzer.Analysis, supportsNegative bool) (confirmedSeverityCounts, summaryClassification) {
	var counts confirmedSeverityCounts
	if analysis != nil {
		for _, finding := range analysis.ValidatedFindings {
			if !finding.IsValid || !strings.EqualFold(finding.Decision, "confirmed") {
				continue
			}
			switch strings.ToLower(finding.Severity) {
			case "critical":
				counts.Critical++
			case "high":
				counts.High++
			case "medium":
				counts.Medium++
			case "low":
				counts.Low++
			default:
				counts.Info++
			}
		}
	}

	switch {
	case counts.Critical > 0:
		return counts, summaryCritical
	case counts.High > 0:
		return counts, summaryHigh
	case counts.Medium > 0:
		return counts, summaryMedium
	case counts.total() > 0:
		return counts, summaryLow
	case !supportsNegative:
		return counts, summaryInconclusive
	case counts.total() == 0:
		return counts, summaryNoConfirmed
	default:
		return counts, summaryLow
	}
}

// supportsNegativeConclusion delegates to the reporter's coverage assessment so
// the terminal and saved report can never disagree about whether a clean
// negative result is justified.
func supportsNegativeConclusion(reconResults *recon.Results, scanResults *scanner.Results, analysis *analyzer.Analysis) bool {
	return reporter.SupportsNegativeConclusion(reconResults, scanResults, analysis)
}

func printSummary(duration time.Duration, reportPath string, subdomains, rawCandidates int,
	analysis *analyzer.Analysis, supportsNegative bool) {
	counts, classification := classifySummary(analysis, supportsNegative)
	manualReview, rejected := 0, 0
	if analysis != nil {
		manualReview = len(analysis.ManualReview)
		rejected = len(analysis.FalsePositives)
	}
	totalConfirmed := counts.total()

	bold := color.New(color.FgWhite, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	dim := color.New(color.FgHiBlack)

	cyan.Println("  ╔════════════════════════════════════════════════════╗")
	cyan.Println("  ║         🎯 HAWKEYE SCAN COMPLETED                 ║")
	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	fmt.Printf("  ⏱️  Scan Duration:     %-26s", duration.Round(time.Second))
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  🌐 Subdomains:        %-26d", subdomains)
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  🔎 Raw candidates:    %-26d", rawCandidates)
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  ✓  Confirmed:         %-26d", totalConfirmed)
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  ?  Manual review:     %-26d", manualReview)
	cyan.Println("║")
	cyan.Print("  ║")
	fmt.Printf("  ✗  Rejected:          %-26d", rejected)
	cyan.Println("║")
	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	bold.Print("  📊 Severity Distribution:                      ")
	cyan.Println("║")

	// Only show actionable severities (hide info)
	severities := []struct {
		icon  string
		name  string
		count int
		c     *color.Color
	}{
		{"🔴", "Critical", counts.Critical, red},
		{"🟠", "High", counts.High, color.New(color.FgHiRed)},
		{"🟡", "Medium", counts.Medium, yellow},
		{"🟢", "Low", counts.Low, green},
	}

	for _, s := range severities {
		cyan.Print("  ║")
		if s.count > 0 {
			s.c.Printf("     %s %-10s → %-5d", s.icon, s.name, s.count)
		} else {
			fmt.Printf("     %s %-10s → %-5d", s.icon, s.name, s.count)
		}
		fmt.Print("                        ")
		cyan.Println("║")
	}

	// Show info count separately if exists
	if counts.Info > 0 {
		cyan.Print("  ║")
		dim.Printf("     ℹ️  Info (hidden) → %-5d", counts.Info)
		fmt.Print("                    ")
		cyan.Println("║")
	}

	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	fmt.Print("  📄 Report Location:                            ")
	cyan.Println("║")
	cyan.Print("  ║")
	safeReportPath := terminalSafe(reportPath)
	bold.Printf("  %s", safeReportPath)
	// Pad to fill the box
	padding := 50 - len(safeReportPath)
	if padding > 0 {
		fmt.Print(strings.Repeat(" ", padding))
	}
	cyan.Println("║")
	cyan.Println("  ╠════════════════════════════════════════════════════╣")
	cyan.Print("  ║")
	dim.Printf("  Developed by @A_cyb3r | HawkEye v%s", appVersion)
	cyan.Println("║")
	cyan.Println("  ╚════════════════════════════════════════════════════╝")

	fmt.Println()
	switch classification {
	case summaryInconclusive:
		yellow.Println("  ⚠️  INCONCLUSIVE: coverage or review status was insufficient; absence of confirmed findings is not a clean bill of health")
	case summaryNoConfirmed:
		green.Println("  ✅ No findings passed the deterministic confirmation gates; manual review may still be required")
	case summaryCritical:
		red.Printf("  🚨 REVIEW NOW: %d critical candidate(s) passed the confirmation gates\n", counts.Critical)
	case summaryHigh:
		color.New(color.FgHiRed).Printf("  ⚠️  REVIEW: %d high-severity candidate(s) passed the confirmation gates\n", counts.High)
	case summaryMedium:
		yellow.Printf("  ⚡ REVIEW: %d medium-severity candidate(s) passed the confirmation gates\n", counts.Medium)
	case summaryLow:
		green.Printf("  ℹ️  REVIEW: %d low/informational candidate(s) passed the confirmation gates\n", totalConfirmed)
	}
	if !supportsNegative && classification != summaryInconclusive {
		yellow.Println("  ⚠️  Coverage or review status was insufficient; confirmed severity is shown, but no absence claim is valid")
	}
	fmt.Println()
	cyan.Println("  📌 Thank you for using HawkEye - Happy Hunting!")
	dim.Println("  🐦 Follow @A_cyb3r on Twitter for updates")
	fmt.Println()
}
