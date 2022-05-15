package utils

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func CheckNS(name string) (bool, error) {
	ns, err := net.LookupNS(name)
	if err != nil {
		var e *net.DNSError
		if errors.As(err, &e) {
			return false, nil
		}
		return false, err
	}
	return len(ns) > 0, nil
}

func SplitDomain(name string) (string, string, error) {
	ok, err := CheckNS(name)
	if err != nil {
		return "", "", err
	}
	if ok {
		return "", name, nil
	}

	l := len(name)
	for i, v := range name {
		if v != '.' || i+1 > l {
			continue
		}

		ok, err := CheckNS(name[i+1:])
		if err != nil {
			return "", "", err
		}
		if ok {
			return name[:i], name[i+1:], nil
		}
	}

	return "", "", fmt.Errorf("dns: failed to find delegated domain for name %q", name)
}

func CheckTXTFromNS(domain string, host string, value string) (bool, error) {
	nsl, err := net.LookupNS(domain)
	if err != nil {
		return false, err
	}

	for _, ns := range nsl {
		res := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network string, address string) (net.Conn, error) {
				dialer := net.Dialer{
					Timeout: 500 * time.Millisecond,
				}
				return dialer.DialContext(ctx, network, ns.Host+":53")
			},
		}

		valid := false
		if txtl, err := res.LookupTXT(context.Background(), host+"."+domain); err == nil {
			for _, txt := range txtl {
				if txt == value {
					valid = true
					break
				}
			}
		}
		if !valid {
			return false, nil
		}
	}

	return true, nil
}
