# Woodpecker JWT Configuration Service

A configuration service that provides cryptographically signed tokens containing Woodpecker CI build and repository information, enabling plugins to verify pipeline details like repository name, branch, and build information.

## Overview

When building Woodpecker CI plugins that need to trust pipeline information (like repository name, current branch, or build details), relying on environment variables isn't always secure as they can be modified by pipeline steps. This service solves this problem by providing cryptographically signed tokens that plugins can verify, ensuring the authenticity of pipeline information they depend on.

## Environment Variables

The service is configured using the following environment variables:

### Required

- `JWT_PRIVATE_KEY`: Ed25519 private key in PEM format used to sign the JWTs
- `LISTEN_ADDR`: Address where the service should listen (e.g., `:8080` or `localhost:8080`)

### Optional

- `WOODPECKER_SIGNATURE_PUBLIC_KEY`: Ed25519 public key in PEM format used to verify incoming Woodpecker requests. Can be retrieved from `https://your-woodpecker-instance/api/signature/public-key`. Required unless signature verification is disabled.
- `WOODPECKER_SIGNATURE_NOVERIFY`: Set to `1` to disable signature verification of incoming requests. See [Security Considerations](#security-considerations) before disabling.
- `JWT_EXPIRATION_TIME`: JWT expiration time in minutes. Defaults to 15 minutes if not specified.

## Injected Environment Variables

The service injects the following environment variables into each pipeline step:

- `CI_SIGNED_REPO`: JWT containing repository information
- `CI_SIGNED_BUILD`: JWT containing build information

The payload of these JWTs corresponds to Woodpecker's repository and pipeline models. For detailed information about the payload structure, refer to:
- Repository payload: [model.Repo](https://pkg.go.dev/go.woodpecker-ci.org/woodpecker/v2/server/model#Repo)
- Pipeline payload: [model.Pipeline](https://pkg.go.dev/go.woodpecker-ci.org/woodpecker/v2/server/model#Pipeline)

## Security Considerations

1. The service must be configured with a private key to sign JWTs. Keep this key secure and rotate it periodically.
2. By default, the service verifies that requests come from your Woodpecker instance using Ed25519 signatures.
3. **IMPORTANT**: If signature verification is disabled (`WOODPECKER_SIGNATURE_NOVERIFY=1`), the service MUST NOT be accessible from pipeline steps. In this configuration, any access to the service would allow obtaining signed tokens for any repository or build.
4. The JWT expiration time should be set short enough to minimize the risk of token reuse while being long enough to accommodate your longest pipeline runs.

## Setup with Woodpecker

1. Generate an Ed25519 key pair for JWT signing
2. Deploy this service with the appropriate environment variables
3. Configure your Woodpecker server to use this service by setting `WOODPECKER_CONFIG_SERVICE_ENDPOINT` to point to this service's URL (do not forget the `/ciconfig` part)
