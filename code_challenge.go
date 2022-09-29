package gateway_plugin_auth

type CodeChallengeMethod string

type CodeChallenge struct {
	Challenge string
	Method    CodeChallengeMethod
}
