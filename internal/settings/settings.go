package settings

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/shlex"
)

var (
	settings *Settings
)

type Settings struct {
	ClouDNSAuthID       string
	ClouDNSAuthPassword string
	DataDir             string
	Certificates        [][]string
	UpdateCommand       []string
	Production          bool
	Force               bool
	Timeout             time.Duration
}

func getString(key string, def string, required bool) (string, error) {
	if v, found := os.LookupEnv(key); found {
		if required && v == "" {
			return "", fmt.Errorf("settings: %s empty", key)
		}
		return v, nil
	}
	if required && def == "" {
		return "", fmt.Errorf("settings: %s missing", key)
	}
	return def, nil
}

func getUint(key string, def uint64, required bool, base int, bitSize int) (uint64, error) {
	v, err := getString(key, strconv.FormatUint(def, base), required)
	if err != nil {
		return 0, err
	}
	v2, err := strconv.ParseUint(v, base, bitSize)
	if err != nil {
		return 0, err
	}
	if required && v2 == 0 {
		return 0, fmt.Errorf("settings: %s empty", key)
	}
	return v2, nil
}

func getBool(key string) bool {
	if v, found := os.LookupEnv(key); found {
		s := strings.ToLower(strings.TrimSpace(v))
		if s == "1" || s == "true" || s == "yes" || s == "on" {
			return true
		}
	}
	return false
}

func Get() (*Settings, error) {
	if settings != nil {
		return settings, nil
	}

	var err error
	s := &Settings{}

	s.ClouDNSAuthID, err = getString("LEDNS_CLOUDNS_AUTH_ID", "", true)
	if err != nil {
		return nil, err
	}

	s.ClouDNSAuthPassword, err = getString("LEDNS_CLOUDNS_AUTH_PASSWORD", "", true)
	if err != nil {
		return nil, err
	}

	s.DataDir, err = getString("LEDNS_DATA_DIR", "/var/lib/ledns", true)
	if err != nil {
		return nil, err
	}
	s.DataDir, err = filepath.Abs(s.DataDir)
	if err != nil {
		return nil, err
	}

	configDir, err := getString("LEDNS_CONFIG_DIR", "/etc/ledns.d", true)
	if err != nil {
		return nil, err
	}
	configDir, err = filepath.Abs(configDir)
	if err != nil {
		return nil, err
	}
	s.Certificates, err = getCertificates(configDir)
	if err != nil {
		return nil, err
	}

	updateCommand, err := getString("LEDNS_UPDATE_COMMAND", "", false)
	if err != nil {
		return nil, err
	}
	s.UpdateCommand, err = shlex.Split(updateCommand)
	if err != nil {
		return nil, err
	}

	s.Production = getBool("LEDNS_PRODUCTION")
	if !s.Production {
		log.Print("WARNING: using staging endpoint for Let's Encrypt. please export LEDNS_PRODUCTION=true to use production endpoint when ready for it.")
	}

	s.Force = getBool("LEDNS_FORCE")

	timeoutMinutes, err := getUint("LEDNS_TIMEOUT_MINUTES", 15, true, 10, 8)
	if err != nil {
		return nil, err
	}
	s.Timeout = time.Duration(timeoutMinutes) * time.Minute

	settings = s

	return s, nil
}
