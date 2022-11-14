FROM golang:1.19-alpine3.16
RUN go install github.com/traefik/yaegi/cmd/yaegi@latest
ENTRYPOINT ["yaegi"]
