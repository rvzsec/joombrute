// Package output normalizes how joombrute reports findings and progress.
// All user-facing output goes through Sink so callers can pick console (with
// ANSI colors) or JSONL (for piping into other tools / SIEM ingest).
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Hit is the canonical "we found something" event.
type Hit struct {
	Time       string `json:"time"`
	Target     string `json:"target"`
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"`
	Outcome    string `json:"outcome"` // "success" | "mfa-required" | "mfa-bypass" | "info-disclosure" | ...
	CaptiveURL string `json:"captive_url,omitempty"`
	// Note is a freeform field for context-specific findings (e.g. CVE id,
	// dumped DB user, etc).
	Note string `json:"note,omitempty"`
}

// Sink is the output abstraction. Implementations must be goroutine-safe.
type Sink interface {
	Hit(Hit)
	Infof(format string, args ...any)
	Warnf(format string, args ...any)
	Errorf(format string, args ...any)
	Debugf(format string, args ...any)
}

// --- Console (TTY-friendly) -----------------------------------------------

const (
	ansiReset  = "\033[0m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
)

// ConsoleSink writes human-readable lines to an io.Writer.
type ConsoleSink struct {
	w     io.Writer
	mu    sync.Mutex
	debug bool
}

// NewConsoleSink returns a sink that writes to w. If debug is true, Debugf
// lines are emitted; otherwise they're dropped.
func NewConsoleSink(w io.Writer, debug bool) *ConsoleSink {
	return &ConsoleSink{w: w, debug: debug}
}

func (c *ConsoleSink) writeln(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, _ = io.WriteString(c.w, s+"\n")
}

func (c *ConsoleSink) Hit(h Hit) {
	if h.Time == "" {
		h.Time = time.Now().Format(time.RFC3339)
	}
	switch h.Outcome {
	case "success":
		c.writeln(fmt.Sprintf("%s[+]%s %s VALID  %s%s:%s%s  -> %s",
			ansiGreen+ansiBold, ansiReset, h.Time,
			ansiBold, h.Username, h.Password, ansiReset, h.Target))
	case "mfa-required":
		c.writeln(fmt.Sprintf("%s[!]%s %s MFA    %s%s:%s%s  -> %s (captive: %s)",
			ansiYellow+ansiBold, ansiReset, h.Time,
			ansiBold, h.Username, h.Password, ansiReset, h.Target, h.CaptiveURL))
	case "mfa-bypass":
		c.writeln(fmt.Sprintf("%s[+]%s %s BYPASS %s%s%s  -> %s (%s)",
			ansiGreen+ansiBold, ansiReset, h.Time,
			ansiBold, h.Username, ansiReset, h.Target, h.Note))
	case "info-disclosure":
		c.writeln(fmt.Sprintf("%s[+]%s %s LEAK   -> %s (%s)",
			ansiGreen+ansiBold, ansiReset, h.Time, h.Target, h.Note))
	default:
		c.writeln(fmt.Sprintf("[+] %s %s -> %s (%s)", h.Time, h.Outcome, h.Target, h.Note))
	}
}

func (c *ConsoleSink) Infof(format string, args ...any) {
	c.writeln(fmt.Sprintf("%s[*]%s "+format, append([]any{ansiCyan, ansiReset}, args...)...))
}

func (c *ConsoleSink) Warnf(format string, args ...any) {
	c.writeln(fmt.Sprintf("%s[!]%s "+format, append([]any{ansiYellow, ansiReset}, args...)...))
}

func (c *ConsoleSink) Errorf(format string, args ...any) {
	c.writeln(fmt.Sprintf("%s[x]%s "+format, append([]any{ansiRed, ansiReset}, args...)...))
}

func (c *ConsoleSink) Debugf(format string, args ...any) {
	if !c.debug {
		return
	}
	c.writeln(fmt.Sprintf("%s[d]%s "+format, append([]any{ansiBlue, ansiReset}, args...)...))
}

// --- JSONL (SIEM / pipe friendly) -----------------------------------------

// jsonLine is the envelope used for every non-Hit JSONL row.
type jsonLine struct {
	Time  string `json:"time"`
	Level string `json:"level"`
	Msg   string `json:"msg"`
}

// JSONLSink emits one JSON object per line.
type JSONLSink struct {
	mu    sync.Mutex
	w     io.Writer
	debug bool
}

func NewJSONLSink(w io.Writer, debug bool) *JSONLSink {
	return &JSONLSink{w: w, debug: debug}
}

func (j *JSONLSink) emit(v any) {
	j.mu.Lock()
	defer j.mu.Unlock()
	enc := json.NewEncoder(j.w)
	_ = enc.Encode(v)
}

func (j *JSONLSink) Hit(h Hit) {
	if h.Time == "" {
		h.Time = time.Now().Format(time.RFC3339)
	}
	j.emit(struct {
		Hit
		Level string `json:"level"`
		Kind  string `json:"kind"`
	}{h, "hit", "hit"})
}

func (j *JSONLSink) logf(level, format string, args ...any) {
	j.emit(jsonLine{
		Time:  time.Now().Format(time.RFC3339),
		Level: level,
		Msg:   fmt.Sprintf(format, args...),
	})
}

func (j *JSONLSink) Infof(format string, args ...any)  { j.logf("info", format, args...) }
func (j *JSONLSink) Warnf(format string, args ...any)  { j.logf("warn", format, args...) }
func (j *JSONLSink) Errorf(format string, args ...any) { j.logf("error", format, args...) }
func (j *JSONLSink) Debugf(format string, args ...any) {
	if !j.debug {
		return
	}
	j.logf("debug", format, args...)
}
