package gateway_plugin_auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPlugin_ServeHTTP(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Error(err)
	}

	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		discoveryConfig := DiscoveryConfiguration{
			Issuer: "http://localhost:8080",
		}
		by, _ := json.Marshal(discoveryConfig)
		_, _ = writer.Write(by)
	}))

	_ = ts.Listener.Close()
	ts.Listener = l
	ts.Start()
	defer ts.Close()

	ctx := context.Background()
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	config := CreateConfig()
	config.Issuer = "http://localhost:8080"
	handler, err := New(ctx, next, config, "test")
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
		if !strings.HasPrefix(b, ErrMissingAuthHeader.Error()) {
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
		if !strings.HasPrefix(b, ErrMalformedAuthHeader.Error()) {
			t.Error(b)
		}
	})

	t.Run("ERR discovery endpoint", func(t *testing.T) {
		config := CreateConfig()
		config.Issuer = "http://localhost"
		handler, err := New(ctx, next, config, "test")
		if err != nil {
			t.Error(err)
		}
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", PrefixBearer+"unverified")
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Error(recorder.Code)
		}
		b := recorder.Body.String()
		if !strings.HasPrefix(b, ErrDiscoveryEndpoint) {
			t.Error(b)
		}
	})

	t.Run("ERR verify token", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
		req.Header.Set("Authorization", PrefixBearer+"unverified")
		if err != nil {
			t.Error(err)
		}
		handler.ServeHTTP(recorder, req)
		if recorder.Code != http.StatusUnauthorized {
			t.Error(recorder.Code)
		}
		b := recorder.Body.String()
		if !strings.HasPrefix(b, ErrVerifyToken) {
			t.Error(b)
		}
	})
}
