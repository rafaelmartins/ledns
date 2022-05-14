package dns

import (
	"context"
	"fmt"
	"time"

	"github.com/rafaelmartins/ledns/internal/dns/cloudns"
)

type DNS interface {
	AddTXTRecord(ctx context.Context, domain string, host string, value string) error
	RemoveTXTRecord(ctx context.Context, domain string, host string, value string) error
	CheckTXTRecord(ctx context.Context, domain string, host string) (bool, error)
}

func GetProvider(ctx context.Context) (DNS, error) {
	// FIXME: detect provider from nameservers
	d, err := cloudns.NewClouDNS(ctx)
	if err != nil {
		return nil, err
	}
	if d != nil {
		return d, nil
	}

	return nil, fmt.Errorf("dns: DNS provider must be configured")
}

func DeployChallenge(ctx context.Context, dns DNS, name string, token string) error {
	prefix, domain, err := splitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	return dns.AddTXTRecord(ctx, domain, host, token)
}

func WaitForChallenge(ctx context.Context, dns DNS, name string) error {
	prefix, domain, err := splitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	for {
		updated, err := dns.CheckTXTRecord(ctx, domain, host)
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
	prefix, domain, err := splitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	return dns.RemoveTXTRecord(ctx, domain, host, token)
}
