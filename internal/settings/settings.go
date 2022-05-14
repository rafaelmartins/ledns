package settings

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/shlex"
)

var (
	settings *Settings
)

type Settings struct {
	ClouDNSAuthID       string
	ClouDNSSubAuthID    string
	ClouDNSAuthPassword string
	DataDir             string
	Certificates        [][]string
	UpdateCommand       []string
	UpdateCommandOnce   []string
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

func getBool(key string, def bool) (bool, error) {
	v, err := getString(key, strconv.FormatBool(def), true)
	if err != nil {
		return false, err
	}
	v2, err := strconv.ParseBool(v)
	if err != nil {
		return false, err
	}
	return v2, nil
}

func Get() (*Settings, error) {
	if settings != nil {
		return settings, nil
	}

	var err error
	s := &Settings{}

	s.ClouDNSAuthID, err = getString("LEDNS_CLOUDNS_AUTH_ID", "", false)
	if err != nil {
		return nil, err
	}

	s.ClouDNSSubAuthID, err = getString("LEDNS_CLOUDNS_SUB_AUTH_ID", "", false)
	if err != nil {
		return nil, err
	}

	s.ClouDNSAuthPassword, err = getString("LEDNS_CLOUDNS_AUTH_PASSWORD", "", false)
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

	updateCommandOnce, err := getString("LEDNS_UPDATE_COMMAND_ONCE", "", false)
	if err != nil {
		return nil, err
	}
	s.UpdateCommandOnce, err = shlex.Split(updateCommandOnce)
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

	s.Production, err = getBool("LEDNS_PRODUCTION", false)
	if err != nil {
		return nil, err
	}
	if !s.Production {
		log.Print("WARNING: using staging endpoint for Let's Encrypt. please export LEDNS_PRODUCTION=true to use production endpoint when ready for it.")
	}

	s.Force, err = getBool("LEDNS_FORCE", false)
	if err != nil {
		return nil, err
	}

	timeoutMinutes, err := getUint("LEDNS_TIMEOUT_MINUTES", 15, true, 10, 8)
	if err != nil {
		return nil, err
	}
	s.Timeout = time.Duration(timeoutMinutes) * time.Minute

	settings = s

	return s, nil
}
