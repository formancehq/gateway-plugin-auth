# gateway-plugin-auth ![Build](https://github.com/formancehq/gateway-plugin-auth/workflows/build/badge.svg)
Traefik plugin for verifying JSON Web Tokens (JWT). Supports JWKS endpoints.
Supports RSA, ECDSA and symmetric keys.

Features:
* RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, HS256, HS384, HS512
* Supports JWK endpoints for fetching keys remotely

## Installation
The plugin needs to be configured in the Traefik static configuration before it can be used.
### Installation with Helm
The following snippet can be used as an example for the values.yaml file:
```values.yaml
pilot:
  enabled: true
  token: xxxxx-xxxx-xxxx

experimental:
  plugins:
    enabled: true

additionalArguments:
- --experimental.plugins.jwt.moduleName=github.com/formancehq/gateway-plugin-auth
- --experimental.plugins.jwt.version=v0.1.0
```

### Installation via command line
```
traefik \
  --experimental.pilot.token=xxxx-xxxx-xxx \
  --experimental.plugins.jwt.moduleName=github.com/formancehq/gateway-plugin-auth \
  --experimental.plugins.jwt.version=v0.1.0
```

## Configuration
The plugin currently supports the following configuration settings: (all fields are optional)

Name | Description
--- | ---
Issuer | Used to verify the issuer of the JWT

## Example configuration
This example uses Kubernetes Custom Resource Descriptors (CRD) :
```
apiVersion: traefik.containo.us/v1alpha1
kind: Middleware
metadata:
  name: jwt
spec:
  plugin:
    jwt:
      Issuer: http://localhost/api/auth
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: test-server
  labels:
    app: test-server
  annotations:
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/router.middlewares: default-jwt@kubernetescrd

```
