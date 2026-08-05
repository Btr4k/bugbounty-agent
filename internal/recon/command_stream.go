package recon

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

const (
	maxPassiveCommandOutputBytes int64 = 8 << 20
	maxKatanaCommandOutputBytes  int64 = 32 << 20
	maxWaybackCommandOutputBytes int64 = 32 << 20
	maxCommandOutputLineBytes          = 64 << 10
	maxWaybackOutputLineBytes          = 256 << 10
)

func readBoundedResponseBody(body io.Reader, limit int64, label string) ([]byte, error) {
	if limit < 1 {
		return nil, fmt.Errorf("%s response limit is invalid", label)
	}
	content, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s response read failed", label)
	}
	if int64(len(content)) > limit {
		return nil, fmt.Errorf("%s response exceeded the %d-byte limit", label, limit)
	}
	return content, nil
}

type boundedCommandStats struct {
	Bytes          int64
	Lines          int
	OversizedLines int
	Truncated      bool
}

var errBoundedOutputLimit = errors.New("bounded command output limit reached")

type boundedLineWriter struct {
	maxBytes    int64
	maxLine     int
	handle      func(string)
	onLimit     func()
	stats       boundedCommandStats
	line        []byte
	discardLine bool
}

func (w *boundedLineWriter) Write(data []byte) (int, error) {
	remaining := w.maxBytes - w.stats.Bytes
	accepted := len(data)
	if int64(accepted) > remaining {
		accepted = int(max(remaining, 0))
	}
	if accepted > 0 {
		w.stats.Bytes += int64(accepted)
		w.consume(data[:accepted])
	}
	if accepted < len(data) {
		w.stats.Truncated = true
		// The record crossing the byte boundary is incomplete and must never be
		// presented to a parser as if it were a complete tool result.
		w.line = w.line[:0]
		w.discardLine = false
		if w.onLimit != nil {
			w.onLimit()
		}
		return accepted, errBoundedOutputLimit
	}
	return len(data), nil
}

func (w *boundedLineWriter) consume(data []byte) {
	for len(data) > 0 {
		newline := bytes.IndexByte(data, '\n')
		content := data
		complete := newline >= 0
		if complete {
			content = data[:newline]
		}
		if !w.discardLine {
			if len(content) > w.maxLine-len(w.line) {
				w.discardLine = true
				w.line = w.line[:0]
			} else {
				w.line = append(w.line, content...)
			}
		}
		if !complete {
			return
		}
		w.finishLine()
		data = data[newline+1:]
	}
}

func (w *boundedLineWriter) finishLine() {
	if w.discardLine {
		w.stats.OversizedLines++
	} else {
		if length := len(w.line); length > 0 && w.line[length-1] == '\r' {
			w.line = w.line[:length-1]
		}
		w.stats.Lines++
		w.handle(string(w.line))
	}
	w.line = w.line[:0]
	w.discardLine = false
}

func (w *boundedLineWriter) finish() {
	if w.stats.Truncated {
		return
	}
	if len(w.line) > 0 || w.discardLine {
		w.finishLine()
	}
}

// executeBoundedLines streams a command's stdout without ever retaining more
// than one bounded line. Stderr is deliberately discarded: tool diagnostics are
// untrusted and can echo URLs, query values, headers, or other secrets. All
// errors returned by this helper contain only fixed labels and numeric status.
// Complete lines read before truncation or process failure are still delivered
// to handle, allowing callers to preserve valid partial coverage.
func executeBoundedLines(
	ctx context.Context,
	tool string,
	cmd *exec.Cmd,
	maxBytes int64,
	maxLineBytes int,
	handle func(string),
) (boundedCommandStats, error) {
	var stats boundedCommandStats
	if maxBytes < 1 || maxLineBytes < 1 {
		return stats, fmt.Errorf("%s output limits are invalid", tool)
	}

	writer := &boundedLineWriter{
		maxBytes: maxBytes,
		maxLine:  maxLineBytes,
		handle:   handle,
		line:     make([]byte, 0, min(maxLineBytes, 4<<10)),
	}
	limitReached := make(chan struct{}, 1)
	writer.onLimit = func() {
		select {
		case limitReached <- struct{}{}:
		default:
		}
	}
	cmd.Stdout = writer
	cmd.Stderr = io.Discard
	configureExternalCommand(cmd)
	if err := cmd.Start(); err != nil {
		return stats, fmt.Errorf("%s failed to start", tool)
	}
	processDone := make(chan struct{})
	go func() {
		select {
		case <-limitReached:
			terminateExternalCommandGroup(cmd)
		case <-ctx.Done():
			terminateExternalCommandGroup(cmd)
		case <-processDone:
		}
	}()
	waitErr := cmd.Wait()
	close(processDone)
	terminateExternalCommandGroup(cmd)
	writer.finish()
	stats = writer.stats
	var coverageErrors []error
	if stats.Truncated {
		coverageErrors = append(coverageErrors, fmt.Errorf("%s output exceeded the %d-byte limit", tool, maxBytes))
	}
	if stats.OversizedLines > 0 {
		coverageErrors = append(coverageErrors, fmt.Errorf("%s discarded %d oversized output line(s)", tool, stats.OversizedLines))
	}
	// A deliberate kill is already represented by the truncation error. Avoid
	// adding a misleading process-failure duplicate in that case.
	if waitErr != nil && !stats.Truncated {
		coverageErrors = append(coverageErrors, safeCommandFailure(ctx, tool, waitErr))
	}
	return stats, joinDiagnosticErrors(coverageErrors...)
}

type diagnosticErrors []error

func (errs diagnosticErrors) Error() string {
	messages := make([]string, 0, len(errs))
	for _, err := range errs {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

func (errs diagnosticErrors) Unwrap() []error {
	return []error(errs)
}

// joinDiagnosticErrors is errors.Join-compatible for errors.Is/As, while its
// rendered message stays on one line so a child process cannot forge log rows.
func joinDiagnosticErrors(candidates ...error) error {
	joined := make(diagnosticErrors, 0, len(candidates))
	for _, err := range candidates {
		if err != nil {
			joined = append(joined, err)
		}
	}
	switch len(joined) {
	case 0:
		return nil
	case 1:
		return joined[0]
	default:
		return joined
	}
}

func safeCommandFailure(ctx context.Context, tool string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		if errors.Is(contextErr, context.DeadlineExceeded) {
			return fmt.Errorf("%s exceeded its time budget", tool)
		}
		return fmt.Errorf("%s was canceled", tool)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if code := exitErr.ExitCode(); code >= 0 {
			return fmt.Errorf("%s exited with status %d", tool, code)
		}
		return fmt.Errorf("%s terminated unexpectedly", tool)
	}
	return fmt.Errorf("%s process failed", tool)
}

// safeHTTPFailure deliberately does not wrap net/http errors: those errors
// routinely contain the full request URL, including sensitive query values.
func safeHTTPFailure(ctx context.Context, operation string, err error) error {
	if contextErr := ctx.Err(); contextErr != nil {
		if errors.Is(contextErr, context.DeadlineExceeded) {
			return fmt.Errorf("%s exceeded its time budget", operation)
		}
		return fmt.Errorf("%s was canceled", operation)
	}
	var networkErr net.Error
	if errors.As(err, &networkErr) && networkErr.Timeout() {
		return fmt.Errorf("%s timed out", operation)
	}
	return fmt.Errorf("%s failed", operation)
}
