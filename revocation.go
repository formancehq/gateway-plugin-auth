package gateway_plugin_auth

type RevocationRequest struct {
	Token         string `schema:"token"`
	TokenTypeHint string `schema:"token_type_hint"`
}
