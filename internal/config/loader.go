package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
)

// LoadFromFile reads haproxy.cfg bytes from disk.
func LoadFromFile(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("config path is required")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}
	return b, nil
}

// HashBytes returns a stable SHA256 hash for the given config bytes.
func HashBytes(cfg []byte) string {
	sum := sha256.Sum256(cfg)
	return hex.EncodeToString(sum[:])
}
