package logger

import (
	"fmt"
	"os"
	"time"

	"github.com/fatih/color"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.SugaredLogger
}

// New creates a new logger instance with console-friendly output
func New(verbose bool) *Logger {
	// Use console encoder for human-readable output
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "", // Hide caller in normal mode
		MessageKey:     "msg",
		StacktraceKey:  "", // Hide stacktrace
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     zapcore.TimeEncoderOfLayout("15:04:05"),
		EncodeDuration: zapcore.StringDurationEncoder,
	}

	level := zap.NewAtomicLevelAt(zap.InfoLevel)
	if verbose {
		level = zap.NewAtomicLevelAt(zap.DebugLevel)
		encoderConfig.CallerKey = "caller"
		encoderConfig.EncodeCaller = zapcore.ShortCallerEncoder
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		level,
	)

	logger := zap.New(core)
	return &Logger{logger.Sugar()}
}

// NewFile creates a logger that writes to both file and stdout
func NewFile(logFile string, verbose bool) (*Logger, error) {
	config := zap.NewProductionConfig()

	if verbose {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	config.OutputPaths = []string{"stdout", logFile}

	logger, err := config.Build()
	if err != nil {
		return nil, err
	}

	return &Logger{logger.Sugar()}, nil
}

// Close flushes the logger
func (l *Logger) Close() {
	l.Sync()
}

// ═══════════════════════════════════════════════════════════
// Professional Progress Output Methods
// ═══════════════════════════════════════════════════════════

var (
	cyanBold   = color.New(color.FgCyan, color.Bold)
	greenBold  = color.New(color.FgGreen, color.Bold)
	yellowBold = color.New(color.FgYellow, color.Bold)
	whiteBold  = color.New(color.FgWhite, color.Bold)
	dimColor   = color.New(color.FgHiBlack)
	redBold    = color.New(color.FgRed, color.Bold)
)

// ToolStart prints a professional "tool starting" message
func (l *Logger) ToolStart(toolName string, detail string) {
	yellowBold.Printf("  ├── 🔄 %s: ", toolName)
	fmt.Printf("%s\n", detail)
}

// ToolDone prints a professional "tool completed" message
func (l *Logger) ToolDone(toolName string, resultCount int, duration time.Duration) {
	greenBold.Printf("  ├── ✅ %s: ", toolName)
	fmt.Printf("completed ")
	whiteBold.Printf("(%d results", resultCount)
	dimColor.Printf(", %s", duration.Round(time.Millisecond))
	whiteBold.Printf(")")
	fmt.Println()
}

// ToolFail prints a professional "tool failed" message
func (l *Logger) ToolFail(toolName string, err error) {
	redBold.Printf("  ├── ❌ %s: ", toolName)
	fmt.Printf("failed - %v\n", err)
}

// ToolSkip prints a "tool skipped" message
func (l *Logger) ToolSkip(toolName string, reason string) {
	dimColor.Printf("  ├── ⏭️  %s: skipped (%s)\n", toolName, reason)
}

// PhaseNote prints a note within a phase
func (l *Logger) PhaseNote(message string) {
	dimColor.Printf("  │   💡 %s\n", message)
}

// SubResult prints a sub-result within a tool
func (l *Logger) SubResult(label string, value interface{}) {
	dimColor.Printf("  │      %s: ", label)
	whiteBold.Printf("%v\n", value)
}
