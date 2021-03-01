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

	le, err := letsencrypt.NewLetsEncrypt(ctx, s.DataDir, s.Production, s.ClouDNSAuthID, s.ClouDNSAuthPassword)
	if err != nil {
		log.Fatal("error: ", err)
	}

	for _, cert := range s.Certificates {
		if len(cert) == 0 {
			continue
		}

		if err := le.GetCertificate(ctx, cert, s.UpdateCommand, s.Force); err != nil {
			log.Fatal("error: ", err)
		}
	}
}
