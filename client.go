package gateway_plugin_auth

import (
	"net/http"
	"strings"
)

// Discover calls the discovery endpoint of the provided issuer and returns its configuration
// It accepts an optional argument "wellknownUrl" which can be used to overide the dicovery endpoint url
func Discover(issuer string, httpClient *http.Client, wellKnownUrl ...string) (*DiscoveryConfiguration, error) {
	wellKnown := strings.TrimSuffix(issuer, "/") + DiscoveryEndpoint
	if len(wellKnownUrl) == 1 && wellKnownUrl[0] != "" {
		wellKnown = wellKnownUrl[0]
	}
	req, err := http.NewRequest("GET", wellKnown, nil)
	if err != nil {
		return nil, err
	}
	discoveryConfig := new(DiscoveryConfiguration)
	err = HttpRequest(httpClient, req, &discoveryConfig)
	if err != nil {
		return nil, err
	}
	if discoveryConfig.Issuer != issuer {
		return nil, ErrIssuerInvalid
	}
	return discoveryConfig, nil
}
