// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// This file contains pure Go helpers that do not depend on CGo.
// They are separated so they can be tested without the Rust library.

package gotatun

import "strings"

// LogLevel constants matching the Rust side.
const (
	LogLevelError = 0
	LogLevelWarn  = 1
	LogLevelInfo  = 2
	LogLevelDebug = 3
	LogLevelTrace = 4
)

// FormatVersion returns a string describing the gotatun backend.
func FormatVersion() string {
	return "gotatun-ffi/0.1.0"
}

// logLevelPrefix returns a log prefix string for the given level.
func logLevelPrefix(level int) string {
	switch level {
	case LogLevelError:
		return "gotatun: "
	case LogLevelWarn:
		return "gotatun: [warn] "
	case LogLevelInfo:
		return "gotatun: [info] "
	case LogLevelDebug:
		return "gotatun: [v1] "
	case LogLevelTrace:
		return "gotatun: [v2] "
	default:
		return "gotatun: "
	}
}

// filterLogLine returns true if the log line should be suppressed,
// matching the filtering done in wglog for wireguard-go.
func filterLogLine(msg string) bool {
	if strings.Contains(msg, "Routine:") && !strings.Contains(msg, "receive incoming") {
		return true
	}
	if strings.Contains(msg, "Failed to send data packet") {
		return true
	}
	return false
}
