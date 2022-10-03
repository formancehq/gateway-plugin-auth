package gateway_plugin_auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt"
)

func TestPlugin_ServeHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Error(err)
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() == discoveryEndpoint {
			cfg := discoveryConfig{
				Issuer:  "http://" + l.Addr().String(),
				JwksURI: "http://" + l.Addr().String() + "/keys",
			}
			by, _ := json.Marshal(cfg)
			_, _ = w.Write(by)
		} else if r.URL.String() == "/keys" {
			keys := jsonWebKeySet{Keys: []jsonWebKey{
				{
					KeyID:     "id",
					Key:       publicKey,
					Algorithm: "HS256",
					Use:       "sig",
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
		if !strings.HasPrefix(b, "jwt.Parse") {
			t.Error(b)
		}
	})

	t.Run("verified token", func(t *testing.T) {
		jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.StandardClaims{
			Issuer: l.Addr().String(),
		})
		jwtTokenString, err := jwtToken.SignedString(privateKey)
		if err != nil {
			t.Error(err)
		}

		token, err := jwt.Parse(jwtTokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return publicKey, nil
		})
		if err != nil {
			t.Error(err)
		}
		if !token.Valid {
			t.Error("invalid token")
		}

		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", prefixBearer+jwtTokenString)
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		b := recorder.Body.String()
		if recorder.Code != http.StatusOK {
			t.Error(recorder.Code, b)
		}
	})
}
