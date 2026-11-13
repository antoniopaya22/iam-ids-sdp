// Package cli has the small helpers shared by the command-line programs: defaults taken
// from environment variables (the lab configures every container through Compose) and
// signal handling.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Env returns the value of key, or def when it is unset or empty.
func Env(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// EnvBool parses key as a boolean ("1", "true", "yes", "on").
func EnvBool(key string, def bool) bool {
	v := strings.ToLower(Env(key, ""))
	switch v {
	case "":
		return def
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// EnvInt parses key as an integer.
func EnvInt(key string, def int) int {
	if n, err := strconv.Atoi(Env(key, "")); err == nil {
		return n
	}
	return def
}

// EnvDuration parses key as a Go duration ("5m", "2s").
func EnvDuration(key string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(Env(key, "")); err == nil {
		return d
	}
	return def
}

// List splits a comma-separated value, dropping empty items.
func List(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// SignalContext is cancelled on SIGINT or SIGTERM.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// Fatalf prints to stderr and exits with code.
func Fatalf(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(code)
}
