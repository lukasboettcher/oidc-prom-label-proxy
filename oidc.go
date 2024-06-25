package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"gopkg.in/yaml.v3"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
)

type OIDCTokenEnforcer struct {
	ClientID   string
	Issuer     string
	ConfigPath string
}

type OIDCConfig struct {
	Tenants []Tenant `yaml:"tenants"`
}

func (c *OIDCConfig) readOIDCConfig(path string) error {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(yamlFile, c)
	if err != nil {
		return err
	}
	return nil
}

type Tenant struct {
	Value  string   `yaml:"value"`
	Groups []string `yaml:"groups"`
	Users  []string `yaml:"users"`
}

func (ote OIDCTokenEnforcer) ExtractLabel(next http.HandlerFunc) http.Handler {
	config := OIDCConfig{}
	err := config.readOIDCConfig(ote.ConfigPath)
	if err != nil {
		log.Printf("Failed to read oidc config, ignoring tenant mapping: %v", err)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		labelValues := []string{}

		provider, err := oidc.NewProvider(r.Context(), ote.Issuer)
		if err != nil {
			prometheusAPIError(w, humanFriendlyErrorMessage(err), http.StatusInternalServerError)
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: ote.ClientID})

		token := r.Header.Get("X-Id-Token")
		if token == "" {
			prometheusAPIError(w, "Authorization header missing", http.StatusUnauthorized)
			return
		}

		// Verify the ID token
		idToken, err := verifier.Verify(r.Context(), token)
		if err != nil {
			prometheusAPIError(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusUnauthorized)
			return
		}

		var claims struct {
			Email  string   `json:"email"`
			Groups []string `json:"groups"`
		}

		if err := idToken.Claims(&claims); err != nil {
			prometheusAPIError(w, fmt.Sprintf("Failed to parse ID token claims: %v", err), http.StatusInternalServerError)
			return
		}

		for _, t := range config.Tenants {
			itTenantMember := false
			for _, g := range t.Groups {
				if slices.Contains(claims.Groups, g) {
					itTenantMember = true
					break
				}
			}
			if itTenantMember || slices.Contains(t.Users, claims.Email) {
				labelValues = append(labelValues, t.Value)
			}
		}

		if len(labelValues) < 1 {
			prometheusAPIError(w, "User is not mapped to any tenants.", http.StatusUnauthorized)
			return
		}

		next(w, r.WithContext(injectproxy.WithLabelValues(r.Context(), []string{strings.Join(labelValues, "|")})))
	})
}
func humanFriendlyErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	errMsg := err.Error()
	return fmt.Sprintf("%s%s.", strings.ToUpper(errMsg[:1]), errMsg[1:])
}

func prometheusAPIError(w http.ResponseWriter, errorMessage string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)

	res := map[string]string{"status": "error", "errorType": "prom-label-proxy", "error": errorMessage}

	if err := json.NewEncoder(w).Encode(res); err != nil {
		log.Printf("error: Failed to encode json: %v", err)
	}
}
