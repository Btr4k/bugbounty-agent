package recon

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Btr4k/bugbounty-agent/internal/config"
)

func TestReadBoundedResponseBodyDetectsTruncation(t *testing.T) {
	content, err := readBoundedResponseBody(bytes.NewBufferString("12345"), 4, "test API")
	if err == nil || content != nil || !strings.Contains(err.Error(), "4-byte limit") {
		t.Fatalf("oversized response was not rejected explicitly: content=%q err=%v", content, err)
	}
	content, err = readBoundedResponseBody(bytes.NewBufferString("1234"), 4, "test API")
	if err != nil || string(content) != "1234" {
		t.Fatalf("response at exact bound was rejected: content=%q err=%v", content, err)
	}
}

func TestExecuteBoundedLinesPreservesOutputOnProcessFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "partial-tool")
	writeExecutable(t, path, `#!/bin/sh
printf 'first\nsecond\n'
printf 'https://example.com/?token=DO_NOT_LOG\n' >&2
exit 7
`)

	var lines []string
	_, err := executeBoundedLines(
		context.Background(),
		"test-tool",
		exec.Command(path),
		1024,
		128,
		func(line string) { lines = append(lines, line) },
	)
	if !slices.Equal(lines, []string{"first", "second"}) {
		t.Fatalf("partial records were not preserved: %v", lines)
	}
	if err == nil || !strings.Contains(err.Error(), "status 7") {
		t.Fatalf("process failure was not surfaced: %v", err)
	}
	if strings.Contains(err.Error(), "DO_NOT_LOG") || strings.ContainsAny(err.Error(), "\r\n") {
		t.Fatalf("stderr/control data leaked into diagnostic: %q", err)
	}
}

func TestExecuteBoundedLinesStopsAtTotalOutputLimit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "large-tool")
	writeExecutable(t, path, `#!/bin/sh
printf 'good\n0123456789abcdef\n'
`)

	var lines []string
	stats, err := executeBoundedLines(
		context.Background(),
		"test-tool",
		exec.Command(path),
		8,
		64,
		func(line string) { lines = append(lines, line) },
	)
	if !slices.Equal(lines, []string{"good"}) {
		t.Fatalf("complete line preceding truncation was not preserved: %v", lines)
	}
	if err == nil || !stats.Truncated || !strings.Contains(err.Error(), "8-byte limit") {
		t.Fatalf("output truncation was not surfaced: stats=%#v err=%v", stats, err)
	}
}

func TestExecuteBoundedLinesDiscardsOversizedLineAndContinues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wide-tool")
	writeExecutable(t, path, `#!/bin/sh
printf 'good\n0123456789\nlast\n'
`)

	var lines []string
	stats, err := executeBoundedLines(
		context.Background(),
		"test-tool",
		exec.Command(path),
		1024,
		8,
		func(line string) { lines = append(lines, line) },
	)
	if !slices.Equal(lines, []string{"good", "last"}) {
		t.Fatalf("oversized line handling lost valid records: %v", lines)
	}
	if err == nil || stats.OversizedLines != 1 || !strings.Contains(err.Error(), "1 oversized") {
		t.Fatalf("oversized line was not surfaced: stats=%#v err=%v", stats, err)
	}
}

func TestExecuteBoundedLinesBoundsOrphanedOutputPipe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "orphan-tool")
	marker := filepath.Join(t.TempDir(), "orphan-survived")
	writeExecutable(t, path, `#!/bin/sh
(sleep 0.25; printf escaped > "$1") &
exit 0
`)
	cmd := exec.Command(path, marker)
	cmd.WaitDelay = 50 * time.Millisecond
	started := time.Now()
	_, err := executeBoundedLines(context.Background(), "test-tool", cmd, 1024, 128, func(string) {})
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("orphaned output pipe was not bounded: %s", elapsed)
	}
	if err == nil {
		t.Fatal("orphaned output pipe coverage failure was not surfaced")
	}
	time.Sleep(350 * time.Millisecond)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("descendant survived the external-command process group: %v", statErr)
	}
}

func TestExternalCommandDoesNotReceiveAmbientSecret(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env-tool")
	writeExecutable(t, path, `#!/bin/sh
if [ -n "${RECON_TEST_SECRET:-}" ]; then
  printf '%s\n' "$RECON_TEST_SECRET"
fi
`)
	t.Setenv("RECON_TEST_SECRET", "DO_NOT_INHERIT")

	cmd := exec.Command(path)
	cmd.Env = config.ExternalToolEnvironment()
	var lines []string
	_, err := executeBoundedLines(context.Background(), "test-tool", cmd, 1024, 128, func(line string) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 0 {
		t.Fatalf("child inherited an ambient secret: %v", lines)
	}
}

func TestSafeHTTPFailureDoesNotExposeRequestURL(t *testing.T) {
	raw := &url.Error{
		Op:  "Get",
		URL: "https://example.com/path?token=DO_NOT_LOG",
		Err: errors.New("network failure\nforged"),
	}
	err := safeHTTPFailure(context.Background(), "test request", raw)
	if err == nil || err.Error() != "test request failed" {
		t.Fatalf("unsafe or unexpected HTTP diagnostic: %q", err)
	}
}
