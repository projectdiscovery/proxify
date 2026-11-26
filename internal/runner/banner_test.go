package runner

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	tagged := &debug.BuildInfo{Main: debug.Module{Version: "v0.0.18"}}
	devel := &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}

	tests := []struct {
		name     string
		injected string
		bi       *debug.BuildInfo
		want     string
	}{
		{"injected version wins", "v0.0.17", tagged, "v0.0.17"},
		{"empty injected uses module version", "", tagged, "v0.0.18"},
		{"dev injected uses module version", "dev", tagged, "v0.0.18"},
		{"devel build stays dev", "dev", devel, "dev"},
		{"no build info stays dev", "dev", nil, "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.injected, tt.bi); got != tt.want {
				t.Fatalf("resolveVersion(%q) = %q, want %q", tt.injected, got, tt.want)
			}
		})
	}
}
