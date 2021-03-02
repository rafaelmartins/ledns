package letsencrypt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

func createCertificateRequest(pk *ecdsa.PrivateKey, names []string) ([]byte, error) {
	return x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: names,
	}, pk)
}

func writeCertificate(certfile string, chain [][]byte) error {
	if err := os.MkdirAll(filepath.Dir(certfile), 0700); err != nil {
		return err
	}

	fp, err := os.OpenFile(certfile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer fp.Close()

	for _, p := range chain {
		if err := pem.Encode(fp, &pem.Block{Type: "CERTIFICATE", Bytes: p}); err != nil {
			return err
		}
	}
	return nil
}

func needsNewCertificate(certfile string, names []string) (bool, time.Time, []string, []string) {
	b, err := ioutil.ReadFile(certfile)
	if err != nil {
		return true, time.Time{}, nil, nil
	}

	chain := [][]byte{}
	for {
		var p *pem.Block
		p, b = pem.Decode(b)
		if p == nil {
			break
		}
		chain = append(chain, p.Bytes)
	}
	if len(chain) == 0 {
		return true, time.Time{}, nil, nil
	}

	crt, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return true, time.Time{}, nil, nil
	}

	// check if expired
	duration := time.Until(crt.NotAfter)
	if duration < 30*24*time.Hour {
		return true, crt.NotAfter, nil, nil
	}

	// check if names changed
	added := []string{}
	for _, n := range names {
		found := false
		for _, o := range crt.DNSNames {
			if n == o {
				found = true
				break
			}
		}
		if !found {
			added = append(added, n)
		}
	}
	removed := []string{}
	for _, o := range crt.DNSNames {
		found := false
		for _, n := range names {
			if o == n {
				found = true
				break
			}
		}
		if !found {
			removed = append(removed, o)
		}
	}
	if len(added) > 0 || len(removed) > 0 {
		return true, time.Time{}, added, removed
	}

	return false, crt.NotAfter, nil, nil
}
