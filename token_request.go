package gateway_plugin_auth

const (
	//GrantTypeCode defines the grant_type `authorization_code` used for the Token Request in the Authorization Code Flow.
	GrantTypeCode GrantType = "authorization_code"
)

type GrantType string

type AccessTokenRequest struct {
	Code                string `schema:"code"`
	RedirectURI         string `schema:"redirect_uri"`
	ClientID            string `schema:"client_id"`
	ClientSecret        string `schema:"client_secret"`
	CodeVerifier        string `schema:"code_verifier"`
	ClientAssertion     string `schema:"client_assertion"`
	ClientAssertionType string `schema:"client_assertion_type"`
}

func (a *AccessTokenRequest) GrantType() GrantType {
	return GrantTypeCode
}

// SetClientID implements op.AuthenticatedTokenRequest.
func (a *AccessTokenRequest) SetClientID(clientID string) {
	a.ClientID = clientID
}

// SetClientSecret implements op.AuthenticatedTokenRequest.
func (a *AccessTokenRequest) SetClientSecret(clientSecret string) {
	a.ClientSecret = clientSecret
}
