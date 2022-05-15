package letsencrypt

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/rafaelmartins/ledns/internal/dns"
	"golang.org/x/crypto/acme"
)

const (
	urlStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	urlProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

type LetsEncrypt struct {
	dir        string
	production bool
	dns        dns.DNS
	client     *acme.Client
}

func NewLetsEncrypt(ctx context.Context, dir string, production bool) (*LetsEncrypt, error) {
	dns, err := dns.GetProvider(ctx)
	if err != nil {
		return nil, err
	}

	rv := &LetsEncrypt{
		dir:        dir,
		production: production,
		dns:        dns,
	}

	client, err := rv.getClient(ctx)
	if err != nil {
		return nil, err
	}
	rv.client = client

	return rv, nil
}

func (l *LetsEncrypt) getPemFilename(name string) string {
	if l.production {
		return name + ".pem"
	}
	return name + "-staging.pem"
}

func (l *LetsEncrypt) getUrl() string {
	if l.production {
		return urlProduction
	}
	return urlStaging
}

func (l *LetsEncrypt) getClient(ctx context.Context) (*acme.Client, error) {
	accountDir := filepath.Join(l.dir, "account")
	if err := os.MkdirAll(accountDir, 0700); err != nil {
		return nil, err
	}

	keyFile := filepath.Join(accountDir, l.getPemFilename("key"))
	if _, err := os.Stat(keyFile); err == nil {
		log.Printf("loading account: %s", keyFile)

		pk, err := loadPrivateKey(keyFile)
		if err != nil {
			return nil, err
		}

		return &acme.Client{
			Key:          pk,
			DirectoryURL: l.getUrl(),
		}, nil
	}

	log.Printf("registering account: %s", keyFile)

	pk, err := createPrivateKey(keyFile)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{
		Key:          pk,
		DirectoryURL: l.getUrl(),
	}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		return nil, err
	}
	return client, nil
}

func (l *LetsEncrypt) cleanupAuthorizations(ctx context.Context, commonName string, urls []string) {
	for _, u := range urls {
		if z, err := l.client.GetAuthorization(ctx, u); err == nil && z.Status == acme.StatusPending {
			log.Printf("[%s: %s] revoking authorization: %s", commonName, z.Identifier.Value, u)
			l.client.RevokeAuthorization(ctx, u)
		}
	}
}

func (l *LetsEncrypt) GetCertificate(ctx context.Context, names []string, force bool) (bool, error) {
	if l.client == nil {
		return false, errors.New("letsencrypt: acme client not defined")
	}

	if len(names) == 0 {
		return false, errors.New("letsencrypt: no name provided")
	}

	commonName := names[0]

	log.Printf("[%s] starting ...", commonName)

	symCertfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("fullchain"))

	if force {
		log.Printf("[%s] requesting new certificate (forced) ...", commonName)
	} else {
		log.Printf("[%s] checking if a new certificate is needed ...", commonName)
		needsNew, expiration, added, removed := needsNewCertificate(symCertfile, names)
		if !needsNew {
			log.Printf("[%s] current certificate expires %s. skipping renew ...", commonName, expiration.Format(time.UnixDate))
			return false, nil
		}
		if expiration.IsZero() {
			if len(added) > 0 || len(removed) > 0 {
				log.Printf("[%s] names changed from current certificate (added %q, removed %q). requesting new ...", commonName, added, removed)
			} else {
				log.Printf("[%s] could not find a suitable certificate. requesting new ...", commonName)
			}
		} else {
			log.Printf("[%s] current certificate expires %s. renewing ...", commonName, expiration.Format(time.UnixDate))
		}
	}

	order, err := l.client.AuthorizeOrder(ctx, acme.DomainIDs(names...))
	if err != nil {
		return false, err
	}
	defer l.cleanupAuthorizations(ctx, commonName, order.AuthzURLs)

	chals := []*acme.Challenge{}
	authTokens := map[string]string{}
	authURIs := []string{}
	for _, u := range order.AuthzURLs {
		z, err := l.client.GetAuthorization(ctx, u)
		if err != nil {
			return false, err
		}

		if z.Status != acme.StatusPending {
			continue
		}

		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return false, fmt.Errorf("letsencrypt: %s: no dns-01 challenge found", z.Identifier.Value)
		}

		log.Printf("[%s: %s] generating challenge record ...", commonName, z.Identifier.Value)
		token, err := l.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return false, err
		}

		log.Printf("[%s: %s] deploying challenge ...", commonName, z.Identifier.Value)
		if err := dns.DeployChallenge(ctx, l.dns, z.Identifier.Value, token); err != nil {
			return false, err
		}
		defer func(ctx context.Context, d dns.DNS, commonName string, name string, token string) {
			log.Printf("[%s: %s] cleaning challenge ...", commonName, name)
			if err := dns.CleanChallenge(ctx, d, name, token); err != nil {
				log.Printf("error: [%s: %s] %s", commonName, name, err)
			}
		}(ctx, l.dns, commonName, z.Identifier.Value, token)

		chals = append(chals, chal)
		authTokens[z.Identifier.Value] = token
		authURIs = append(authURIs, z.URI)
	}

	if len(authTokens) > 0 {
		log.Printf("[%s] waiting for DNS propagation of challenges ...", commonName)
		for name, token := range authTokens {
			if err := dns.WaitForChallenge(ctx, l.dns, name, token); err != nil {
				return false, err
			}
		}
	}

	if len(chals) > 0 {
		log.Printf("[%s] accepting challenges ...", commonName)
		for _, chal := range chals {
			if _, err := l.client.Accept(ctx, chal); err != nil {
				return false, err
			}
		}
	}

	if len(authURIs) > 0 {
		log.Printf("[%s] waiting for autorizations ...", commonName)
		for _, uri := range authURIs {
			if _, err := l.client.WaitAuthorization(ctx, uri); err != nil {
				return false, err
			}
		}
	}

	ts := time.Now().UTC().Format("20060102150405")

	keyfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("privkey-"+ts))
	pk, err := createPrivateKey(keyfile)
	if err != nil {
		return false, err
	}

	csr, err := createCertificateRequest(pk, names)
	if err != nil {
		return false, err
	}

	chain, _, err := l.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return false, err
	}

	certfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("fullchain-"+ts))
	if err := writeCertificate(certfile, chain); err != nil {
		return false, err
	}

	log.Printf("[%s] updating symlinks ...", commonName)

	// FIXME: make this symlink replacement actually atomic/safe

	symKeyfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("privkey"))
	if _, err := os.Lstat(symKeyfile); err == nil {
		os.Remove(symKeyfile)
	}
	if err := os.Symlink(l.getPemFilename("privkey-"+ts), symKeyfile); err != nil {
		return false, err
	}

	if _, err := os.Lstat(symCertfile); err == nil {
		os.Remove(symCertfile)
	}
	if err := os.Symlink(l.getPemFilename("fullchain-"+ts), symCertfile); err != nil {
		return false, err
	}

	log.Printf("[%s] certificate request done", commonName)
	return true, nil
}

func (l *LetsEncrypt) RunCommand(names []string, command []string) error {
	if len(command) > 0 {
		log.Printf("[%s] running update command %q ...", names[0], command)

		cmd := exec.Command(command[0], command[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(
			os.Environ(),
			"LEDNS_COMMON_NAME="+names[0],
			"LEDNS_CERTIFICATE="+filepath.Join(l.dir, "certs", names[0], l.getPemFilename("fullchain")),
		)
		return cmd.Run()
	}
	return nil
}

func (l *LetsEncrypt) RunCommandOnce(command []string) error {
	if len(command) > 0 {
		log.Printf("running update command %q ...", command)

		cmd := exec.Command(command[0], command[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}
	return nil
}
