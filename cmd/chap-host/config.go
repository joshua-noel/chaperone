package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/joshua-noel/chaperone/internal/grant"
)

// Config is the helper's one configuration file. It holds no secret: a public
// key, a loopback URL, and where each allowlisted script lives. The file must
// be writable only by the operator (L1-17 sets the ACL): whoever edits it can
// point the helper at another chapd key.
type Config struct {
	// ChapdURL is chapd's loopback address, for example "http://127.0.0.1:55398".
	ChapdURL string `json:"chapd_url"`
	// ChapdPublicKey is the pinned Ed25519 public key that signs grants,
	// 32 bytes as unpadded base64url.
	ChapdPublicKey string `json:"chapd_public_key"`
	// ChapdTokenFile holds the bearer token chapd expects from the helper. It
	// lives in the operator's profile, where the agent account cannot read it.
	ChapdTokenFile string `json:"chapd_token_file"`
	// StateDir holds the nonce file and private script copies. Default: the
	// directory of the config file.
	StateDir string `json:"state_dir"`
	// Scripts maps allowlisted runbook names to the absolute path of the script
	// each runs. A runbook with no entry is refused.
	Scripts map[string]string `json:"scripts"`
}

// LoadConfig reads and checks the config at path.
func LoadConfig(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.StateDir == "" {
		c.StateDir = filepath.Dir(path)
	}
	if err := c.check(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) check() error {
	u, err := url.Parse(c.ChapdURL)
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return errors.New("chapd_url must look like http://127.0.0.1:55398")
	}
	if host := u.Hostname(); host != "localhost" {
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return errors.New("chapd_url must be a loopback address")
		}
	}
	if _, err := c.PublicKey(); err != nil {
		return err
	}
	if !filepath.IsAbs(c.ChapdTokenFile) {
		return errors.New("chapd_token_file must be an absolute path")
	}
	if !filepath.IsAbs(c.StateDir) {
		return errors.New("state_dir must be an absolute path")
	}
	for name, p := range c.Scripts {
		if _, ok := grant.Lookup(name); !ok {
			return fmt.Errorf("scripts: %q is not an allowlisted runbook (known: %s)", name, strings.Join(grant.Names(), ", "))
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("scripts[%q] must be an absolute path", name)
		}
	}
	return nil
}

// PublicKey decodes the pinned chapd key.
func (c *Config) PublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(c.ChapdPublicKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("chapd_public_key must be 32 bytes as unpadded base64url")
	}
	return ed25519.PublicKey(raw), nil
}

// defaultConfigPath is %LOCALAPPDATA%\Chaperone\host\chap-host.json.
func defaultConfigPath() (string, error) {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		return "", errors.New("LOCALAPPDATA is not set; pass -config")
	}
	return filepath.Join(base, "Chaperone", "host", "chap-host.json"), nil
}
