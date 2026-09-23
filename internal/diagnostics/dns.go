package diagnostics

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/kmpoltorak/ai-network-incident-investigator/internal/domain"
)

type DNSResult struct {
	Hostname  string   `json:"hostname"`
	Addresses []string `json:"addresses"`
	// ResponseStatus is one of resolved, nxdomain, timeout, error.
	ResponseStatus string `json:"response_status"`
	Error          string `json:"error,omitempty"`
}

func (r DNSResult) result() Result {
	if r.ResponseStatus == "resolved" {
		return Result{
			Health:  domain.Healthy,
			Summary: fmt.Sprintf("%s resolved to %s", r.Hostname, strings.Join(r.Addresses, ", ")),
			Data:    r,
		}
	}
	return Result{
		Health:  domain.Down,
		Summary: fmt.Sprintf("%s failed to resolve (%s): %s", r.Hostname, r.ResponseStatus, r.Error),
		Data:    r,
	}
}

// DNSTool resolves a hostname with the Go resolver.
type DNSTool struct {
	Resolver *net.Resolver
}

func (DNSTool) Name() string { return DNS }

func (d DNSTool) Run(ctx context.Context, t Target) (Result, error) {
	if err := t.Validate(); err != nil {
		return Result{}, err
	}
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	r := DNSResult{Hostname: t.Host, Addresses: []string{}}
	addrs, err := resolver.LookupHost(ctx, t.Host)
	var dnsErr *net.DNSError
	switch {
	case err == nil:
		r.ResponseStatus = "resolved"
		r.Addresses = addrs
	case ctx.Err() != nil:
		return Result{}, fmt.Errorf("dns lookup: %w", ctx.Err())
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		r.ResponseStatus, r.Error = "nxdomain", dnsErr.Err
	case errors.As(err, &dnsErr) && dnsErr.IsTimeout:
		r.ResponseStatus, r.Error = "timeout", dnsErr.Err
	default:
		r.ResponseStatus, r.Error = "error", err.Error()
	}
	return r.result(), nil
}
