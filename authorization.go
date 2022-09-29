package gateway_plugin_auth

// AuthRequest according to:
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type AuthRequest struct {
	Scopes       SpaceDelimitedArray `json:"scope" schema:"scope"`
	ResponseType ResponseType        `json:"response_type" schema:"response_type"`
	ClientID     string              `json:"client_id" schema:"client_id"`
	RedirectURI  string              `json:"redirect_uri" schema:"redirect_uri"`

	State string `json:"state" schema:"state"`
	Nonce string `json:"nonce" schema:"nonce"`

	ResponseMode ResponseMode        `json:"response_mode" schema:"response_mode"`
	Display      Display             `json:"display" schema:"display"`
	Prompt       SpaceDelimitedArray `json:"prompt" schema:"prompt"`
	MaxAge       *uint               `json:"max_age" schema:"max_age"`
	IDTokenHint  string              `json:"id_token_hint" schema:"id_token_hint"`
	LoginHint    string              `json:"login_hint" schema:"login_hint"`
	ACRValues    []string            `json:"acr_values" schema:"acr_values"`

	CodeChallenge       string              `json:"code_challenge" schema:"code_challenge"`
	CodeChallengeMethod CodeChallengeMethod `json:"code_challenge_method" schema:"code_challenge_method"`

	//RequestParam enables OIDC requests to be passed in a single, self-contained parameter (as JWT, called Request Object)
	RequestParam string `schema:"request"`
}

// GetRedirectURI returns the redirect_uri value for the ErrAuthRequest interface
func (a *AuthRequest) GetRedirectURI() string {
	return a.RedirectURI
}

// GetResponseType returns the response_type value for the ErrAuthRequest interface
func (a *AuthRequest) GetResponseType() ResponseType {
	return a.ResponseType
}

// GetState returns the optional state value for the ErrAuthRequest interface
func (a *AuthRequest) GetState() string {
	return a.State
}
