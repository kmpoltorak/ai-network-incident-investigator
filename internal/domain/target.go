package domain

import (
	"errors"
	"net/netip"
	"regexp"
	"strings"
)

// RFC 1123 label: alphanumeric, hyphens inside, 1-63 chars.
var hostnameLabel = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateHost accepts an IP address or an RFC 1123 hostname. It is the
// single gate in front of every diagnostic tool, so it deliberately rejects
// anything that could be interpreted as a command-line flag or shell syntax.
func ValidateHost(host string) error {
	if host == "" {
		return errors.New("is required")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) > 253 {
		return errors.New("must be at most 253 characters")
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if !hostnameLabel.MatchString(label) {
			return errors.New("must be a valid hostname or IP address")
		}
	}
	return nil
}

// IsIP reports whether host is a literal IP address.
func IsIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}
