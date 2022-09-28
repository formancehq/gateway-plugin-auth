package gateway_plugin_auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/zitadel/oidc/pkg/client"
	"github.com/zitadel/oidc/pkg/client/rp"
	"github.com/zitadel/oidc/pkg/oidc"
	"github.com/zitadel/oidc/pkg/op"
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
	spew.Dump(r)
	token, err := getBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	c := http.DefaultClient
	discoveryConfig, err := client.Discover(a.issuer, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	remotePublicKeys := rp.NewRemoteKeySet(c, discoveryConfig.JwksURI)
	accessTokenVerifier := op.NewAccessTokenVerifier(a.issuer, remotePublicKeys)
	if _, err := op.VerifyAccessToken(r.Context(), token, accessTokenVerifier); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	a.next.ServeHTTP(w, r)
}

var (
	ErrMissingAuthHeader   = errors.New("missing authorization header")
	ErrMalformedAuthHeader = errors.New("malformed authorization header")
)

func getBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("authorization")
	if authHeader == "" {
		return "", ErrMissingAuthHeader
	}

	if !strings.HasPrefix(authHeader, strings.ToLower(oidc.PrefixBearer)) &&
		!strings.HasPrefix(authHeader, oidc.PrefixBearer) {
		return "", ErrMalformedAuthHeader
	}

	token := strings.TrimPrefix(authHeader, strings.ToLower(oidc.PrefixBearer))
	token = strings.TrimPrefix(token, oidc.PrefixBearer)

	return token, nil
}
