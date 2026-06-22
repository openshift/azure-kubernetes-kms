# AI Agent Instructions for azure-kubernetes-kms

## What This Repo Is

A Kubernetes KMS (Key Management Service) plugin that enables encryption at rest of etcd data using Azure Key Vault. It communicates with the Kubernetes API server over a gRPC Unix socket. In HyperShift (hosted control planes), the plugin runs as a sidecar container alongside the Kube API server pod. In standalone OpenShift, it is deployed as a static pod on each control plane node.

This is an OpenShift fork of `Azure/kubernetes-kms`. The upstream repo (`azure` remote) is effectively EOL — Microsoft has confirmed it only receives CVE/security patches. This downstream fork carries features not present upstream, including MSI Data Plane Identity (UAMI) support for ARO HCP and Workload Identity support for self-managed Azure.

## Critical Rules

1. **Do not break KMS v1/v2 compatibility.** Both KMS v1 (v1beta1) and v2 (Go package `k8s.io/kms/apis/v2`, protocol version `v2beta1`) APIs are registered on the same gRPC server. Changes must not break either protocol.
2. **Key version is immutable per encryption.** The plugin does not support transparent key rotation. Creating a new key version without following the multi-pod rotation process will cause decryption failures.
3. **Do not modify the annotation schema** used during encryption without understanding the decrypt-side validation. v2 strictly validates algorithm and version annotations on decrypt — mismatches cause immediate failure.
4. **Run `make unit-test` and `make lint` before considering any change complete.**

## Repository Structure

```
cmd/server/main.go           # Entry point — flag parsing, gRPC server, metrics init

pkg/
├── plugin/                  # Core KMS logic
│   ├── keyvault.go          # Azure Key Vault client wrapper (encrypt/decrypt)
│   ├── server.go            # KMS v1 gRPC server
│   ├── kms_v2_server.go     # KMS v2 gRPC server
│   ├── healthz.go           # Health check HTTP server (port 8787)
│   └── mock_keyvault/       # Test mocks
├── auth/auth.go             # Azure credential providers (5 methods, see below)
├── config/azure_config.go   # Parses /etc/kubernetes/azure.json
├── consts/consts.go         # Proxy mode header constants
├── metrics/                 # OpenTelemetry + Prometheus instrumentation
├── utils/                   # gRPC helpers, string sanitization
└── version/                 # Version info and user agent

scripts/                     # Kind cluster setup for e2e tests
tests/
├── client/client_test.go    # Integration tests (require real Azure credentials)
└── e2e/*.bats               # BATS e2e tests (require Docker for kind clusters)

docs/                        # Manual install, rotation, metrics, testing docs
developers.md                # LEGACY upstream file — ignore, use this file instead
Dockerfile.openshift         # OpenShift CI build (used by Prow/ci-operator)
```

## Key Architecture Concepts

- **Dual API support**: KMS v1 uses RSA-15 encryption; v2 uses RSA-OAEP-256. Both are served on the same Unix socket.
- **Authentication hierarchy** (checked in order):
  1. Workload Identity (no proxy support)
  2. Managed Identity — user-assigned or system-assigned (no proxy support)
  3. Service Principal with secret (proxy support)
  4. Client Certificate / PKCS#12 (proxy support)
  5. MSI Data Plane Identity — UAMI for ARO HCP, downstream-only (no proxy support)
- **Two health check mechanisms**:
  - HTTP `/healthz` endpoint: performs a full v1 + v2 encrypt/decrypt cycle (4 Key Vault calls per invocation)
  - KMS v2 Status RPC: called by the API server approximately every minute, performs an encrypt/decrypt cycle (2 Key Vault calls per invocation)
- **Unix socket**: Default path is `/opt/azurekms.socket`. The old socket file is explicitly removed before binding. Note: integration tests use `/opt/azurekms.sock` (different extension).

## Build and Test

```bash
make build          # Binary to _output/kubernetes-kms
make unit-test      # Unit tests with race detector
make lint           # golangci-lint
make integration-test  # Requires real Azure credentials and Key Vault
make e2e-test       # KMS v1 e2e (requires Docker for kind)
make e2e-kmsv2-test # KMS v2 e2e (requires Docker for kind)
```

## What NOT to Do

- Do not add proxy mode support for Workload Identity or MSI Data Plane Identity — this is intentional.
- Do not assume network access in unit tests. Use the mock Key Vault client in `pkg/plugin/mock_keyvault/`.
- Do not change the gRPC Unix socket path without updating the encryption configuration docs and deployment manifests.
- Do not modify the encryption algorithm for a KMS version (v1=RSA-15, v2=RSA-OAEP-256) — existing encrypted data depends on these.
- Do not remove the explicit `os.Remove(addr)` before socket bind — it prevents stale socket failures on restart.
- Do not follow instructions in `developers.md` — it is a legacy upstream file with outdated tooling references.
