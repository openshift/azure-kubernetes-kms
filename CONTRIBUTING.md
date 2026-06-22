# Contributing to azure-kubernetes-kms

azure-kubernetes-kms is a Kubernetes KMS plugin that enables encryption at rest of etcd data using Azure Key Vault. This is an OpenShift fork of `Azure/kubernetes-kms`.

The upstream repo is effectively EOL (confirmed by Microsoft) and only receives CVE/security patches. This fork carries downstream-only features including MSI Data Plane Identity (UAMI) support for ARO HCP and Workload Identity support for self-managed Azure. New feature work happens here, not upstream.

The repo contains a legacy `developers.md` from upstream with outdated tooling references (Go 1.9, `dep`). Ignore it — this file and `AGENTS.md` are the current contribution guides.

## Development Workflow

1. Fork the repo and clone your fork.
2. Create a feature branch from `main`.
3. Make your changes, add or update tests.
4. Run verification locally before pushing:

```bash
make build       # Binary to _output/kubernetes-kms
make unit-test   # Unit tests with race detector
make lint        # golangci-lint
```

5. Push your branch and open a PR against `openshift/azure-kubernetes-kms:main`.

## Pull Request Guidelines

- Keep PRs focused. One logical change per PR.
- Write clear commit messages. Reference Jira tickets where applicable.
- Include unit tests for new functionality. Use the mock Key Vault client in `pkg/plugin/mock_keyvault/` — do not assume network access in unit tests.
- PRs require approval from at least one approver listed in the `OWNERS` file.

## Testing

| Command | What it runs |
|---------|-------------|
| `make build` | Compile binary to `_output/kubernetes-kms` |
| `make unit-test` | Unit tests with race detector |
| `make lint` | golangci-lint |
| `make integration-test` | Integration tests (requires real Azure credentials and Key Vault) |
| `make e2e-test` | KMS v1 e2e tests (requires Docker for kind clusters) |
| `make e2e-kmsv2-test` | KMS v2 e2e tests (requires Docker for kind clusters) |

E2E tests use the BATS framework and create kind clusters with the plugin deployed. They verify actual secret encryption/decryption in etcd.

## Code Conventions

- Follow standard Go conventions (gofmt, govet).
- Use existing patterns in the package you are modifying.
- Both KMS v1 (v1beta1) and v2 (v2beta1) APIs are registered on the same gRPC server. Changes must not break either protocol.
- Do not modify the encryption algorithm for a KMS version (v1=RSA-15, v2=RSA-OAEP-256) — existing encrypted data depends on these.

## Areas Requiring Extra Care

- **Annotation schema** (`pkg/plugin/`): v2 strictly validates algorithm and version annotations on decrypt. Mismatches cause immediate decryption failure.
- **Key rotation**: The plugin does not support transparent key rotation. See `docs/rotation.md` for the multi-pod rotation process.
- **Authentication** (`pkg/auth/`): Supports multiple Azure auth methods in a specific order. Do not add proxy support for Workload Identity — this is an intentional limitation.

## CI

CI runs via OpenShift's CI infrastructure (Prow / ci-operator) using `Dockerfile.openshift` for builds. All `make unit-test` and `make lint` checks must pass for a PR to merge.
