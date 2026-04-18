package local

import (
	"testing"
)

func TestDirOf(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"/etc/haproxy/haproxy.cfg", "/etc/haproxy"},
		{"/haproxy.cfg", "/"},
		{"haproxy.cfg", "/"},
		{"/a/b/c/d.txt", "/a/b/c"},
		{"/single", "/"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := dirOf(tt.input)
			if got != tt.want {
				t.Errorf("dirOf(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestFileHash(t *testing.T) {
	// fileHash delegates to config.LoadFromFile + config.HashBytes;
	// verify it returns an error for a non-existent file.
	_, err := fileHash("/tmp/nonexistent-haproxy-operator-test-file")
	if err == nil {
		t.Error("fileHash: expected error for nonexistent file, got nil")
	}
}
