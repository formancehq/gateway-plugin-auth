package gateway_plugin_auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/zitadel/oidc/pkg/client"
	"github.com/zitadel/oidc/pkg/client/rs"
	"github.com/zitadel/oidc/pkg/oidc"
)

type Config struct {
	Issuer string `json:"issuer"`
}

func CreateConfig() *Config {
	return &Config{}
}

type Plugin struct {
	next   http.Handler
	name   string
	issuer string
}

var ErrEmptyIssuer = errors.New("issuer cannot be empty")

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Issuer == "" {
		return nil, ErrEmptyIssuer
	}

	return &Plugin{
		next:   next,
		name:   name,
		issuer: config.Issuer,
	}, nil
}

func (a *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("authorization")
	if authHeader == "" {
		http.Error(w, "auth header missing", http.StatusUnauthorized)
		return
	}

	if !strings.HasPrefix(authHeader, oidc.PrefixBearer) {
		http.Error(w, "invalid auth header", http.StatusUnauthorized)
		return
	}

	// DISCOVERY
	discoveryConfig, err := client.Discover(a.issuer, http.DefaultClient)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	fmt.Printf("discovery config: %+v\n", discoveryConfig)

	clientID := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	res, err := rs.NewResourceServerClientCredentials(a.issuer, clientID, clientSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// INTROSPECTION
	token := strings.TrimPrefix(authHeader, oidc.PrefixBearer)
	resp, err := rs.Introspect(r.Context(), res, token)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	fmt.Printf("CLAIMS: %+v\n", resp.GetClaims())

	if !resp.IsActive() {
		http.Error(w, "inactive token", http.StatusUnauthorized)
		return
	}

	a.next.ServeHTTP(w, r)
}
