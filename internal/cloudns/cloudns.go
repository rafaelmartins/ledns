package cloudns

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	apiUrl = "https://api.cloudns.net"
)

type ClouDNS struct {
	authID       string
	authPassword string
}

func NewClouDNS(ctx context.Context, authID string, authPassword string) (*ClouDNS, error) {
	rv := &ClouDNS{
		authID:       authID,
		authPassword: authPassword,
	}

	if err := rv.request(ctx, "/dns/login.json", nil, nil); err != nil {
		return nil, err
	}
	return rv, nil
}

func (c *ClouDNS) request(ctx context.Context, endpoint string, args map[string]string, v interface{}) error {
	purl, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		return err
	}
	purl.Path = endpoint

	pargs := url.Values{}
	for k, v := range args {
		pargs.Set(k, v)
	}
	pargs.Set("auth-id", c.authID)
	pargs.Set("auth-password", c.authPassword)
	purl.RawQuery = pargs.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, purl.String(), nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	if b := strings.TrimSpace(string(body)); len(b) > 0 && b[0] != '{' { // not json :(
		// we can still use json package to try to parse this, though.
		// e.g. for `/dns/is-updated.json` this is either `true` or `false`
		if v != nil {
			return json.Unmarshal(body, v)
		}
		return nil
	}

	type status struct {
		Status            string `json:"status"`
		StatusDescription string `json:"statusDescription"`
	}
	st := &status{}
	if err := json.Unmarshal(body, st); err != nil {
		return err
	}
	if strings.ToLower(st.Status) == "failed" {
		return fmt.Errorf("cloudns: %s", st.StatusDescription)
	}

	if v != nil {
		return json.Unmarshal(body, v)
	}
	return nil
}

func (c *ClouDNS) DeployChallenge(ctx context.Context, name string, token string) error {
	prefix, domain, err := splitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	return c.request(ctx, "/dns/add-record.json", map[string]string{
		"domain-name": domain,
		"record-type": "TXT",
		"host":        host,
		"record":      token,
		"ttl":         "60",
	}, nil)
}

func (c *ClouDNS) WaitForChallenge(ctx context.Context, name string) error {
	_, domain, err := splitDomain(name)
	if err != nil {
		return err
	}
	for {
		updated := false
		c.request(ctx, "/dns/is-updated.json", map[string]string{
			"domain-name": domain,
		}, &updated)
		if updated {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		time.Sleep(30 * time.Second)
	}
}

func (c *ClouDNS) CleanChallenge(ctx context.Context, name string, token string) error {
	prefix, domain, err := splitDomain(name)
	if err != nil {
		return err
	}
	host := "_acme-challenge"
	if prefix != "" {
		host += "." + prefix
	}

	type record struct {
		Record string `json:"record"`
	}
	records := map[string]*record{}

	if err := c.request(ctx, "/dns/records.json", map[string]string{
		"domain-name":   domain,
		"type":          "TXT",
		"host":          host,
		"rows-per-page": "100",
	}, &records); err != nil {
		return err
	}

	deleted := 0
	for id, record := range records {
		if record.Record != token {
			continue
		}

		if deleted > 0 {
			time.Sleep(time.Second)
		}

		if err := c.request(ctx, "/dns/delete-record.json", map[string]string{
			"domain-name": domain,
			"record-id":   id,
		}, nil); err != nil {
			return err
		}

		deleted++
	}

	return nil
}
