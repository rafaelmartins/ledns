package letsencrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
)

func createPrivateKey(keyfile string) (*ecdsa.PrivateKey, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	p, err := x509.MarshalECPrivateKey(pk)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(keyfile), 0700); err != nil {
		return nil, err
	}

	fp, err := os.OpenFile(keyfile, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	if err := pem.Encode(fp, &pem.Block{Type: "EC PRIVATE KEY", Bytes: p}); err != nil {
		return nil, err
	}

	return pk, nil
}

func loadPrivateKey(keyfile string) (*ecdsa.PrivateKey, error) {
	fp, err := os.Open(keyfile)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	b, err := ioutil.ReadAll(fp)
	if err != nil {
		return nil, err
	}

	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("letsencrypt: failed to parse private key: %s", keyfile)
	}

	return x509.ParseECPrivateKey(p.Bytes)
}
