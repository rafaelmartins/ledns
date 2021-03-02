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

	"github.com/rafaelmartins/ledns/internal/cloudns"
	"golang.org/x/crypto/acme"
)

const (
	urlStaging    = "https://acme-staging-v02.api.letsencrypt.org/directory"
	urlProduction = "https://acme-v02.api.letsencrypt.org/directory"
)

type LetsEncrypt struct {
	dir        string
	production bool
	dns        *cloudns.ClouDNS
	client     *acme.Client
}

func NewLetsEncrypt(ctx context.Context, dir string, production bool, cloudnsAuthID string, cloudnsAuthPassword string) (*LetsEncrypt, error) {
	dns, err := cloudns.NewClouDNS(ctx, cloudnsAuthID, cloudnsAuthPassword)
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

func (l *LetsEncrypt) GetCertificate(ctx context.Context, names []string, force bool) error {
	if l.client == nil {
		return errors.New("letsencrypt: acme client not defined")
	}

	if len(names) == 0 {
		return errors.New("letsencrypt: no name provided")
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
			return nil
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
		return err
	}
	defer l.cleanupAuthorizations(ctx, commonName, order.AuthzURLs)

	chals := []*acme.Challenge{}
	authNames := []string{}
	authURIs := []string{}
	for _, u := range order.AuthzURLs {
		z, err := l.client.GetAuthorization(ctx, u)
		if err != nil {
			return err
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
			return fmt.Errorf("letsencrypt: %s: no dns-01 challenge found", z.Identifier.Value)
		}

		log.Printf("[%s: %s] generating challenge record ...", commonName, z.Identifier.Value)
		token, err := l.client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return err
		}

		log.Printf("[%s: %s] deploying challenge ...", commonName, z.Identifier.Value)
		if err := l.dns.DeployChallenge(ctx, z.Identifier.Value, token); err != nil {
			return err
		}
		defer func(ctx context.Context, dns *cloudns.ClouDNS, commonName string, name string, token string) {
			log.Printf("[%s: %s] cleaning challenge ...", commonName, name)
			if err := dns.CleanChallenge(ctx, name, token); err != nil {
				log.Printf("error: [%s: %s] %s", commonName, name, err)
			}
		}(ctx, l.dns, commonName, z.Identifier.Value, token)

		chals = append(chals, chal)
		authNames = append(authNames, z.Identifier.Value)
		authURIs = append(authURIs, z.URI)
	}

	if len(authNames) > 0 {
		log.Printf("[%s] waiting for DNS propagation of challenges ...", commonName)
		for _, name := range authNames {
			if err := l.dns.WaitForChallenge(ctx, name); err != nil {
				return err
			}
		}
	}

	if len(chals) > 0 {
		log.Printf("[%s] accepting challenges ...", commonName)
		for _, chal := range chals {
			if _, err := l.client.Accept(ctx, chal); err != nil {
				return err
			}
		}
	}

	if len(authURIs) > 0 {
		log.Printf("[%s] waiting for autorizations ...", commonName)
		for _, uri := range authURIs {
			if _, err := l.client.WaitAuthorization(ctx, uri); err != nil {
				return err
			}
		}
	}

	ts := time.Now().UTC().Format("20060102150405")

	keyfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("privkey-"+ts))
	pk, err := createPrivateKey(keyfile)
	if err != nil {
		return err
	}

	csr, err := createCertificateRequest(pk, names)
	if err != nil {
		return err
	}

	chain, _, err := l.client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}

	certfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("fullchain-"+ts))
	if err := writeCertificate(certfile, chain); err != nil {
		return err
	}

	log.Printf("[%s] updating symlinks ...", commonName)

	// FIXME: make this symlink replacement actually atomic/safe

	symKeyfile := filepath.Join(l.dir, "certs", commonName, l.getPemFilename("privkey"))
	if _, err := os.Lstat(symKeyfile); err == nil {
		os.Remove(symKeyfile)
	}
	if err := os.Symlink(l.getPemFilename("privkey-"+ts), symKeyfile); err != nil {
		return err
	}

	if _, err := os.Lstat(symCertfile); err == nil {
		os.Remove(symCertfile)
	}
	if err := os.Symlink(l.getPemFilename("fullchain-"+ts), symCertfile); err != nil {
		return err
	}

	log.Printf("[%s] certificate request done", commonName)
	return nil
}

func (l *LetsEncrypt) RunCommand(names []string, command []string) error {
	if len(command) > 0 {
		log.Printf("[%s] running update command %q ...", names[0], command)

		cmd := exec.Command(command[0], command[1:]...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
	}
	return nil
}
