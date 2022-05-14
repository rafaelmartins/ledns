package dns

import (
	"errors"
	"fmt"
	"net"
)

func checkNS(name string) (bool, error) {
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

func splitDomain(name string) (string, string, error) {
	ok, err := checkNS(name)
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

		ok, err := checkNS(name[i+1:])
		if err != nil {
			return "", "", err
		}
		if ok {
			return name[:i], name[i+1:], nil
		}
	}

	return "", "", fmt.Errorf("cloudns: failed to find delegated domain for name %q", name)
}
