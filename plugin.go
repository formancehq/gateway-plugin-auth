package gateway_plugin_auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/formancehq/gateway-plugin-auth/pkg/client"
	"github.com/formancehq/gateway-plugin-auth/pkg/client/rp"
	"github.com/formancehq/gateway-plugin-auth/pkg/oidc"
	"github.com/formancehq/gateway-plugin-auth/pkg/op"
	"github.com/pkg/errors"
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

func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.Issuer == "" {
		return nil, ErrEmptyIssuer
	}

	return &Plugin{
		next:   next,
		name:   name,
		issuer: config.Issuer,
	}, nil
}

var (
	ErrDiscoveryEndpoint = "discovery endpoint"
	ErrVerifyToken       = "verify token"
)

func (p *Plugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token, err := getBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	c := http.DefaultClient
	discoveryConfig, err := client.Discover(p.issuer, c)
	if err != nil {
		http.Error(w, errors.Wrap(err, ErrDiscoveryEndpoint).Error(), http.StatusUnauthorized)
		return
	}

	remotePublicKeys := rp.NewRemoteKeySet(c, discoveryConfig.JwksURI)
	accessTokenVerifier := op.NewAccessTokenVerifier(p.issuer, remotePublicKeys)
	if _, err := op.VerifyAccessToken(r.Context(), token, accessTokenVerifier); err != nil {
		http.Error(w, errors.Wrap(err, ErrVerifyToken).Error(), http.StatusUnauthorized)
		return
	}

	p.next.ServeHTTP(w, r)
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
