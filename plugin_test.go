package gateway_plugin_auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	gateway_plugin_auth "github.com/formancehq/gateway-plugin-auth"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/require"
)

func TestPlugin_ServeHTTP(t *testing.T) {
	mockOIDC, err := mockoidc.Run()
	require.NoError(t, err)
	defer func() {
		require.NoError(t, mockOIDC.Shutdown())
	}()

	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})
	ctx := context.Background()

	config := gateway_plugin_auth.CreateConfig()
	config.Issuer = mockOIDC.Issuer()
	handler, err := gateway_plugin_auth.New(ctx, next, config, "test")
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	t.Run("without token", func(t *testing.T) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		require.NoError(t, err)
		handler.ServeHTTP(recorder, req)
		require.Equal(t, http.StatusUnauthorized, recorder.Code)
	})
}
