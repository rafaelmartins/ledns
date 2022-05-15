package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

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

	sigInt := make(chan os.Signal)
	signal.Notify(sigInt, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	go func() {
		<-sigInt
		cancel()
	}()
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

	le, err := letsencrypt.NewLetsEncrypt(ctx, s.DataDir, s.Production, s.DNSProvider)
	if err != nil {
		exit(err)
	}

	badCerts := [][]string{}
	newCerts := [][]string{}
	for _, cert := range s.Certificates {
		if len(cert) == 0 {
			continue
		}

		newCert, err := le.GetCertificate(ctx, cert, s.Force)
		if err != nil {
			log.Print("error: ", err)
			badCerts = append(badCerts, cert)
			continue
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

	if len(badCerts) > 0 {
		l.Close()
		log.Fatalf("error: failed to get certificate(s): %q", badCerts)
	}
}
