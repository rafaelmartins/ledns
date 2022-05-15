package hetzner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/rafaelmartins/ledns/internal/dns/utils"
)

const (
	apiUrl = "https://dns.hetzner.com"
)

type Hetzner struct {
	apiKey string
}

func NewHetzner(apiKey string) (*Hetzner, error) {
	rv := &Hetzner{
		apiKey: apiKey,
	}

	// just check if authentication works
	if err := rv.request(context.Background(), http.MethodGet, "/api/v1/zones", map[string]string{
		"per_page": "1",
	}, nil, nil); err != nil {
		return nil, err
	}

	return rv, nil
}

func (c *Hetzner) request(ctx context.Context, method string, endpoint string, args map[string]string, data map[string]interface{}, v interface{}) error {
	purl, err := url.ParseRequestURI(apiUrl)
	if err != nil {
		return err
	}
	purl.Path = endpoint

	pargs := url.Values{}
	for k, v := range args {
		pargs.Set(k, v)
	}
	purl.RawQuery = pargs.Encode()

	var rbody io.Reader
	if data != nil {
		a, err := json.Marshal(data)
		if err != nil {
			return err
		}
		rbody = bytes.NewBuffer(a)
	}

	req, err := http.NewRequestWithContext(ctx, method, purl.String(), rbody)
	if err != nil {
		return err
	}

	if data != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	req.Header.Add("Auth-API-Token", c.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		type response struct {
			Message string `json:"message"`
		}
		e := response{}
		if err := json.Unmarshal(body, &e); err != nil {
			return fmt.Errorf("hetzner: request failed (%d): %s", resp.StatusCode, body)
		}
		return fmt.Errorf("hetzner: request failed (%d): %s", resp.StatusCode, e.Message)
	}

	if v != nil {
		return json.Unmarshal(body, v)
	}
	return nil
}

func (c *Hetzner) getZoneID(ctx context.Context, domain string) (string, error) {
	type result struct {
		Zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"zones"`
	}

	v := result{}
	if err := c.request(ctx, http.MethodGet, "/api/v1/zones", map[string]string{
		"name": domain,
	}, nil, &v); err != nil {
		return "", err
	}

	if len(v.Zones) == 0 {
		return "", fmt.Errorf("hetzner: zone not found: %s", domain)
	}
	if len(v.Zones) > 1 {
		return "", fmt.Errorf("hetzner: more than one zone found: %s", domain)
	}
	if domain != v.Zones[0].Name {
		return "", fmt.Errorf("hetzner: returned zone does not match: %q != %q", domain, v.Zones[0].Name)
	}

	return v.Zones[0].ID, nil
}

func (c *Hetzner) AddTXTRecord(ctx context.Context, domain string, host string, value string) error {
	zid, err := c.getZoneID(ctx, domain)
	if err != nil {
		return err
	}

	return c.request(ctx, http.MethodPost, "/api/v1/records", nil, map[string]interface{}{
		"name":    host,
		"ttl":     60,
		"type":    "TXT",
		"value":   value,
		"zone_id": zid,
	}, nil)
}

func (c *Hetzner) RemoveTXTRecord(ctx context.Context, domain string, host string, value string) error {
	zid, err := c.getZoneID(ctx, domain)
	if err != nil {
		return err
	}

	type result struct {
		Records []struct {
			ID    string `json:"id"`
			Name  string `json:"name"`
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"records"`
	}

	v := result{}
	if err := c.request(ctx, http.MethodGet, "/api/v1/records", map[string]string{
		"zone_id": zid,
	}, nil, &v); err != nil {
		return err
	}

	deleted := 0
	for _, rec := range v.Records {
		if rec.Name != host || rec.Type != "TXT" || rec.Value != value {
			continue
		}

		if deleted > 0 {
			time.Sleep(time.Second)
		}

		if err := c.request(ctx, http.MethodDelete, "/api/v1/records/"+rec.ID, nil, nil, nil); err != nil {
			return err
		}

		deleted++
	}

	return nil
}

func (c *Hetzner) CheckTXTRecord(ctx context.Context, domain string, host string, value string) (bool, error) {
	return utils.CheckTXTFromNS(domain, host, value)
}
