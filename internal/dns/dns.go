package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/rafaelmartins/ledns/internal/dns/cloudns"
	"github.com/rafaelmartins/ledns/internal/dns/hetzner"
	"github.com/rafaelmartins/ledns/internal/dns/utils"
)

type DNS interface {
	AddTXTRecord(ctx context.Context, domain string, host string, value string) error
	RemoveTXTRecord(ctx context.Context, domain string, host string, value string) error
	CheckTXTRecord(ctx context.Context, domain string, host string, value string) (bool, error)
}

func GetProvider(ctx context.Context) (DNS, error) {
	// FIXME: detect provider from nameservers
	c, err := cloudns.NewClouDNS(ctx)
	if err != nil {
		return nil, err
	}
	if c != nil {
		return c, nil
	}

	h, err := hetzner.NewHetzner(ctx)
	if err != nil {
		return nil, err
	}
	if h != nil {
		return h, nil
	}

	return nil, fmt.Errorf("dns: DNS provider must be configured")
}

func DeployChallenge(ctx context.Context, dns DNS, name string, token string) error {
	prefix, domain, err := utils.SplitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	return dns.AddTXTRecord(ctx, domain, host, token)
}

func WaitForChallenge(ctx context.Context, dns DNS, name string, token string) error {
	prefix, domain, err := utils.SplitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	for {
		updated, err := dns.CheckTXTRecord(ctx, domain, host, token)
		if err != nil {
			return err
		}
		if updated {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		time.Sleep(5 * time.Second)
	}
}

func CleanChallenge(ctx context.Context, dns DNS, name string, token string) error {
	prefix, domain, err := utils.SplitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	return dns.RemoveTXTRecord(ctx, domain, host, token)
}
