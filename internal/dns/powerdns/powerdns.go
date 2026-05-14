package powerdns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"rafaelmartins.com/p/ledns/internal/dns/utils"
)

type PowerDNS struct {
	apiUrl string
	apiKey string
	server string
}

func NewPowerDNS(apiUrl string, apiKey string, server string) (*PowerDNS, error) {
	if server == "" {
		server = "localhost"
	}
	rv := &PowerDNS{
		apiUrl: apiUrl,
		apiKey: apiKey,
		server: server,
	}

	// just check if authentication works
	if err := rv.request(context.Background(), http.MethodGet, "/api/v1/servers/"+rv.server+"/zones", nil, nil); err != nil {
		return nil, err
	}
	return rv, nil
}

func (p *PowerDNS) request(ctx context.Context, method string, endpoint string, data map[string]any, v any) error {
	purl, err := url.ParseRequestURI(p.apiUrl)
	if err != nil {
		return err
	}
	purl.Path = endpoint

	var rbody io.Reader
	if data != nil {
		b := &bytes.Buffer{}
		if err = json.NewEncoder(b).Encode(data); err != nil {
			return err
		}
		rbody = b
	}

	req, err := http.NewRequestWithContext(ctx, method, purl.String(), rbody)
	if err != nil {
		return err
	}

	if data != nil {
		req.Header.Add("Content-Type", "application/json")
	}

	req.Header.Add("X-API-Key", p.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	isJson := strings.ToLower(resp.Header.Get("Content-Type")) == "application/json"

	if resp.StatusCode >= 400 {
		if isJson {
			b := struct {
				Error  string   `json:"error"`
				Errors []string `json:"errors"`
			}{}
			if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
				return err
			}

			if len(b.Errors) > 0 {
				return fmt.Errorf("powerdns: request: %d: %s: %q", resp.StatusCode, b.Error, b.Errors)
			}
			return fmt.Errorf("powerdns: request: %d: %s", resp.StatusCode, b.Error)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("powerdns: request: %d: %s", resp.StatusCode, body)
	}

	if isJson && v != nil {
		return json.NewDecoder(resp.Body).Decode(v)
	}
	return nil
}

func (p *PowerDNS) AddTXTRecord(ctx context.Context, domain string, host string, value string) error {
	return p.request(ctx, http.MethodPatch, "/api/v1/servers/"+p.server+"/zones/"+domain+".", map[string]any{
		"rrsets": []map[string]any{
			{
				"name":       host + "." + domain + ".",
				"type":       "TXT",
				"ttl":        60,
				"changetype": "EXTEND",
				"records": []map[string]any{
					{
						"content":  "\"" + value + "\"",
						"disabled": false,
					},
				},
			},
		},
	}, nil)
}

func (p *PowerDNS) CheckTXTRecord(ctx context.Context, domain string, host string, value string) (bool, error) {
	return utils.CheckTXTFromNS(ctx, domain, host, value)
}

func (p *PowerDNS) RemoveTXTRecord(ctx context.Context, domain string, host string, value string) error {
	return p.request(ctx, http.MethodPatch, "/api/v1/servers/"+p.server+"/zones/"+domain+".", map[string]any{
		"rrsets": []map[string]any{
			{
				"name":       host + "." + domain + ".",
				"type":       "TXT",
				"changetype": "DELETE",
			},
		},
	}, nil)
}
