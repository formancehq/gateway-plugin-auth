package gateway_plugin_auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlugin_ServeHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}

	publicKeyBytes := []byte{}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == discoveryEndpoint {
			cfg := DiscoveryConfig{
				Issuer:  "http://" + l.Addr().String(),
				JwksURI: "http://" + l.Addr().String() + "/keys",
			}
			by, _ := json.Marshal(cfg)
			_, _ = w.Write(by)
		} else if r.URL.String() == "/keys" {
			keys := Keys{Keys: []Key{
				{
					Use: "sig",
					Kid: "id",
					Kty: "RSA",
					Alg: "RS256",
					N:   base64.RawURLEncoding.EncodeToString(publicKeyBytes),
					E:   "AQAB",
				},
			}}
			by, _ := json.Marshal(keys)
			_, _ = w.Write(by)
		}
	}))

	_ = ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	config := CreateConfig()
	config.Issuer = "http://" + l.Addr().String()
	handler, err := New(ctx, next, config, "")
	if err != nil {
		t.Error(err)
	}

	t.Run("ERR missing header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Error(recorder.Code)
		}
		b := recorder.Body.String()
		if !strings.HasPrefix(b, ErrHeaderAuthMissing.Error()) {
			t.Error(b)
		}
	})

	t.Run("ERR malformed header", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", "malformed")
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Error(recorder.Code)
		}
		b := recorder.Body.String()
		if !strings.HasPrefix(b, ErrHeaderAuthMalformed.Error()) {
			t.Error(b)
		}
	})

	t.Run("ERR invalid format token", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", prefixBearer+"invalid format")
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Error(recorder.Code)
		}
		b := recorder.Body.String()
		if !strings.HasPrefix(b, ErrTokenInvalidFormat) {
			t.Error(b)
		}
	})

	t.Run("ERR unverified token", func(t *testing.T) {
		invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", prefixBearer+invalidToken)
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Error(recorder.Code)
		}
		b := recorder.Body.String()
		if !strings.HasPrefix(b, ErrTokenVerification) {
			t.Error(b)
		}
	})
}
