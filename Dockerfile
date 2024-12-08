FROM golang:1.23-alpine AS builder
WORKDIR /src
ARG TARGETOS
ARG TARGETARCH
COPY . .
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o woodpecker-signed-env

FROM alpine:3.21
COPY --from=builder /src/woodpecker-signed-env /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/woodpecker-signed-env"]
