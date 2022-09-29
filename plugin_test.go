package gateway_plugin_auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gatewaypluginauth "github.com/formancehq/gateway-plugin-auth"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/require"
)

func TestPlugin_ServeHTTP(t *testing.T) {
	mockOIDC, err := mockoidc.Run()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, mockOIDC.Shutdown())
	}()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	config := gatewaypluginauth.CreateConfig()
	config.Issuer = mockOIDC.Issuer()
	handler, err := gatewaypluginauth.New(ctx, next, config, "test")
	require.NoError(t, err)

	t.Run("ERR missing header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		handler.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusUnauthorized, recorder.Code)
		require.True(t, strings.HasPrefix(recorder.Body.String(),
			gatewaypluginauth.ErrMissingAuthHeader.Error()))
	})

	t.Run("ERR malformed header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", "malformed")
		require.NoError(t, err)
		handler.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusUnauthorized, recorder.Code)
		require.True(t, strings.HasPrefix(recorder.Body.String(),
			gatewaypluginauth.ErrMalformedAuthHeader.Error()))
	})

	t.Run("ERR discovery endpoint", func(t *testing.T) {
		config := gatewaypluginauth.CreateConfig()
		config.Issuer = "http://localhost"
		handler, err := gatewaypluginauth.New(ctx, next, config, "test")
		require.NoError(t, err)
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", gatewaypluginauth.PrefixBearer+"unverified")
		require.NoError(t, err)
		handler.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusUnauthorized, recorder.Code)
		require.True(t, strings.HasPrefix(recorder.Body.String(),
			gatewaypluginauth.ErrDiscoveryEndpoint))
	})

	t.Run("ERR verify token", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", gatewaypluginauth.PrefixBearer+"unverified")
		require.NoError(t, err)
		handler.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusUnauthorized, recorder.Code)
		require.True(t, strings.HasPrefix(recorder.Body.String(),
			gatewaypluginauth.ErrVerifyToken))
	})
}
