package main

import (
	"context"
	"log"
	"path/filepath"

	"github.com/rafaelmartins/ledns/internal/letsencrypt"
	"github.com/rafaelmartins/ledns/internal/lock"
	"github.com/rafaelmartins/ledns/internal/settings"
)

func main() {
	log.SetPrefix("ledns: ")
	log.SetFlags(0)

	s, err := settings.Get()
	if err != nil {
		log.Fatal("error: ", err)
	}

	log.Printf("starting ...")
	log.Printf("    timeout: %s", s.Timeout)
	log.Printf("    data directory: %s", s.DataDir)
	log.Printf("    certificates:")
	if len(s.Certificates) > 0 {
		for _, cert := range s.Certificates {
			log.Printf("        %q", cert)
		}
	} else {
		log.Printf("        no certificates defined. exiting ...")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()

	l, err := lock.NewLock(filepath.Join(s.DataDir, "locks", "lock"))
	if err != nil {
		log.Fatal("error: ", err)
	}
	defer l.Close()

	exit := func(e error) {
		l.Close()
		log.Fatal("error: ", e)
	}

	le, err := letsencrypt.NewLetsEncrypt(ctx, s.DataDir, s.Production, s.ClouDNSAuthID, s.ClouDNSSubAuthID, s.ClouDNSAuthPassword)
	if err != nil {
		exit(err)
	}

	newCerts := [][]string{}
	for _, cert := range s.Certificates {
		if len(cert) == 0 {
			continue
		}

		newCert, err := le.GetCertificate(ctx, cert, s.Force)
		if err != nil {
			exit(err)
		}
		if newCert {
			newCerts = append(newCerts, cert)
		}
	}

	if len(s.UpdateCommandOnce) > 0 {
		if len(newCerts) > 0 {
			if err := le.RunCommandOnce(s.UpdateCommandOnce); err != nil {
				exit(err)
			}
		}
	} else {
		for _, cert := range newCerts {
			if err := le.RunCommand(cert, s.UpdateCommand); err != nil {
				exit(err)
			}
		}
	}
}
