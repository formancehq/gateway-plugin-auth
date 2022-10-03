# gateway-plugin-auth ![Build](https://github.com/formancehq/gateway-plugin-auth/workflows/build/badge.svg)
Traefik plugin for verifying JSON Web Tokens (JWT). Supports public keys, certificates or JWKS endpoints.
Supports RSA, ECDSA and symmetric keys.

Features:
* RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512, HS256, HS384, HS512
* Certificates or public keys can be configured in the dynamic config 
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
Keys | Used to validate JWT signature. Multiple keys are supported. Allowed values include certificates, public keys, symmetric keys. In case the value is a valid URL, the plugin will fetch keys from the JWK endpoint.
Alg | Used to verify which PKI algorithm is used in the JWT
Iss | Used to verify the issuer of the JWT
Aud | Used to verify the audience of the JWT
JwtHeaders | Map used to inject JWT payload fields as an HTTP header

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
      Keys:
        - https://samples.auth0.com/.well-known/jwks.json
        - |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
          vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
          aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
          tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
          e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
          V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
          MwIDAQAB
        -----END PUBLIC KEY-----
      JwtHeaders:
        Subject: sub
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
