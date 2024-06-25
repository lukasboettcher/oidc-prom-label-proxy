package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"syscall"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/metalmatze/signal/internalserver"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"gopkg.in/yaml.v3"

	"github.com/prometheus-community/prom-label-proxy/injectproxy"
)

func main() {
	var (
		insecureListenAddress  string
		internalListenAddress  string
		upstream               string
		label                  string
		enableLabelAPIs        bool
		unsafePassthroughPaths string // Comma-delimited string.
		errorOnReplace         bool
		regexMatch             bool
		oidcClientId           string
		oidcIssuer             string
		oidcConfigPath         string
	)

	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagset.StringVar(&insecureListenAddress, "insecure-listen-address", "", "The address the prom-label-proxy HTTP server should listen on.")
	flagset.StringVar(&internalListenAddress, "internal-listen-address", "", "The address the internal prom-label-proxy HTTP server should listen on to expose metrics about itself.")
	flagset.StringVar(&upstream, "upstream", "", "The upstream URL to proxy to.")
	flagset.StringVar(&label, "label", "", "The label name to enforce in all proxied PromQL queries.")
	flagset.BoolVar(&enableLabelAPIs, "enable-label-apis", true, "When specified proxy allows to inject label to label APIs like /api/v1/labels and /api/v1/label/<name>/values. "+
		"NOTE: Enable with care because filtering by matcher is not implemented in older versions of Prometheus (>= v2.24.0 required) and Thanos (>= v0.18.0 required, >= v0.23.0 recommended). If enabled and "+
		"any labels endpoint does not support selectors, the injected matcher will have no effect.")
	flagset.StringVar(&unsafePassthroughPaths, "unsafe-passthrough-paths", "", "Comma delimited allow list of exact HTTP path segments that should be allowed to hit upstream URL without any enforcement. "+
		"This option is checked after Prometheus APIs, you cannot override enforced API endpoints to be not enforced with this option. Use carefully as it can easily cause a data leak if the provided path is an important "+
		"API (like /api/v1/configuration) which isn't enforced by prom-label-proxy. NOTE: \"all\" matching paths like \"/\" or \"\" and regex are not allowed.")
	flagset.BoolVar(&errorOnReplace, "error-on-replace", false, "When specified, the proxy will return HTTP status code 400 if the query already contains a label matcher that differs from the one the proxy would inject.")
	flagset.BoolVar(&regexMatch, "regex-match", true, "When specified, the tenant name is treated as a regular expression. In this case, only one tenant name should be provided.")
	flagset.StringVar(&oidcClientId, "oidc-client-id", "", "The Clien ID of the oidc issuer.")
	flagset.StringVar(&oidcIssuer, "oidc-issuer", "", "The URL for the OIDC issuer.")
	flagset.StringVar(&oidcConfigPath, "oidc-config", "", "The path to a config file for mapping tenants to groups.")

	//nolint: errcheck // Parse() will exit on error.
	flagset.Parse(os.Args[1:])
	if label == "" {
		log.Fatalf("-label flag cannot be empty")
	}

	if oidcClientId == "" || oidcIssuer == "" {
		log.Fatalf("oidcClientId and oidcIssuer are required")
	}

	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		log.Fatalf("Failed to build parse upstream URL: %v", err)
	}

	if upstreamURL.Scheme != "http" && upstreamURL.Scheme != "https" {
		log.Fatalf("Invalid scheme for upstream URL %q, only 'http' and 'https' are supported", upstream)
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	opts := []injectproxy.Option{injectproxy.WithPrometheusRegistry(reg)}
	if enableLabelAPIs {
		opts = append(opts, injectproxy.WithEnabledLabelsAPI())
	}

	if len(unsafePassthroughPaths) > 0 {
		opts = append(opts, injectproxy.WithPassthroughPaths(strings.Split(unsafePassthroughPaths, ",")))
	}

	if errorOnReplace {
		opts = append(opts, injectproxy.WithErrorOnReplace())
	}

	if regexMatch {
		opts = append(opts, injectproxy.WithRegexMatch())
	}

	extractLabeler := OIDCTokenEnforcer{ClientID: oidcClientId, Issuer: oidcIssuer, ConfigPath: oidcConfigPath}

	var g run.Group

	{
		// Run the insecure HTTP server.
		routes, err := injectproxy.NewRoutes(upstreamURL, label, extractLabeler, opts...)
		if err != nil {
			log.Fatalf("Failed to create injectproxy Routes: %v", err)
		}

		mux := http.NewServeMux()
		mux.Handle("/", routes)

		l, err := net.Listen("tcp", insecureListenAddress)
		if err != nil {
			log.Fatalf("Failed to listen on insecure address: %v", err)
		}

		srv := &http.Server{Handler: mux}

		g.Add(func() error {
			log.Printf("Listening insecurely on %v", l.Addr())
			if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
				log.Printf("Server stopped with %v", err)
				return err
			}
			return nil
		}, func(error) {
			srv.Close()
		})
	}

	if internalListenAddress != "" {
		// Run the internal HTTP server.
		h := internalserver.NewHandler(
			internalserver.WithName("Internal prom-label-proxy API"),
			internalserver.WithPrometheusRegistry(reg),
			internalserver.WithPProf(),
		)
		// Run the HTTP server.
		l, err := net.Listen("tcp", internalListenAddress)
		if err != nil {
			log.Fatalf("Failed to listen on internal address: %v", err)
		}

		srv := &http.Server{Handler: h}

		g.Add(func() error {
			log.Printf("Listening on %v for metrics and pprof", l.Addr())
			if err := srv.Serve(l); err != nil && err != http.ErrServerClosed {
				log.Printf("Internal server stopped with %v", err)
				return err
			}
			return nil
		}, func(error) {
			srv.Close()
		})
	}

	g.Add(run.SignalHandler(context.Background(), syscall.SIGINT, syscall.SIGTERM))

	if err := g.Run(); err != nil {
		if !errors.As(err, &run.SignalError{}) {
			log.Printf("Server stopped with %v", err)
			os.Exit(1)
		}
		log.Print("Caught signal; exiting gracefully...")
	}
}

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
