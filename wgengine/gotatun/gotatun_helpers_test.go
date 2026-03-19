// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package gotatun

import "testing"

func TestFormatVersion(t *testing.T) {
	v := FormatVersion()
	if v != "gotatun-ffi/0.1.0" {
		t.Errorf("FormatVersion() = %q, want %q", v, "gotatun-ffi/0.1.0")
	}
}

func TestLogLevelPrefix(t *testing.T) {
	tests := []struct {
		level int
		want  string
	}{
		{LogLevelError, "gotatun: "},
		{LogLevelWarn, "gotatun: [warn] "},
		{LogLevelInfo, "gotatun: [info] "},
		{LogLevelDebug, "gotatun: [v1] "},
		{LogLevelTrace, "gotatun: [v2] "},
		{-1, "gotatun: "},
		{99, "gotatun: "},
	}
	for _, tt := range tests {
		got := logLevelPrefix(tt.level)
		if got != tt.want {
			t.Errorf("logLevelPrefix(%d) = %q, want %q", tt.level, got, tt.want)
		}
	}
}

func TestFilterLogLine(t *testing.T) {
	tests := []struct {
		msg  string
		want bool
	}{
		// Should be filtered
		{"Routine: something", true},
		{"peer Routine: sending keepalive", true},
		{"Failed to send data packet to 1.2.3.4", true},

		// Should NOT be filtered
		{"", false},
		{"normal log message", false},
		{"Routine: receive incoming handshake", false},
		{"receive incoming data", false},
		{"Sending handshake initiation", false},
		{"Received handshake response", false},
	}
	for _, tt := range tests {
		got := filterLogLine(tt.msg)
		if got != tt.want {
			t.Errorf("filterLogLine(%q) = %v, want %v", tt.msg, got, tt.want)
		}
	}
}

func TestLogLevelConstants(t *testing.T) {
	// Verify ordering
	if LogLevelError >= LogLevelWarn {
		t.Error("error should be < warn")
	}
	if LogLevelWarn >= LogLevelInfo {
		t.Error("warn should be < info")
	}
	if LogLevelInfo >= LogLevelDebug {
		t.Error("info should be < debug")
	}
	if LogLevelDebug >= LogLevelTrace {
		t.Error("debug should be < trace")
	}
}
