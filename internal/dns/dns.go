package dns

import (
	"context"
	"time"

	"github.com/rafaelmartins/ledns/internal/dns/utils"
)

type DNS interface {
	AddTXTRecord(ctx context.Context, domain string, host string, value string) error
	CheckTXTRecord(ctx context.Context, domain string, host string, value string) (bool, error)
	RemoveTXTRecord(domain string, host string, value string) error
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

func CleanChallenge(dns DNS, name string, token string) error {
	prefix, domain, err := utils.SplitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	return dns.RemoveTXTRecord(domain, host, token)
}
