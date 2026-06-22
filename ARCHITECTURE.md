# Architecture: azure-kubernetes-kms

## Overview

azure-kubernetes-kms is a Kubernetes KMS plugin that enables encryption at rest of etcd data using Azure Key Vault. The plugin exposes a gRPC server over a Unix socket that the Kubernetes API server calls during secret encryption and decryption operations. In HyperShift (hosted control planes), the plugin runs as a sidecar container alongside the Kube API server pod. In standalone OpenShift, it is deployed as a static pod on each control plane node.

This is an OpenShift fork of `Azure/kubernetes-kms`. The upstream repo is effectively EOL (confirmed by Microsoft) and only receives CVE/security patches. This fork carries downstream-only features including MSI Data Plane Identity (UAMI) support for ARO HCP and Workload Identity support for self-managed Azure.

## Component Architecture

```
Kubernetes API Server
  │
  │  gRPC (unix:///opt/azurekms.socket)
  ↓
KMS Plugin (static pod per control plane node)
  ├── gRPC Server
  │   ├── KMS v1 Server (v1beta1, RSA-15)
  │   └── KMS v2 Server (k8s.io/kms/apis/v2, protocol v2beta1, RSA-OAEP-256)
  ├── Key Vault Client (encrypt/decrypt via Azure SDK)
  ├── Auth Provider (5 methods — see Authentication section)
  ├── Health Check Server (HTTP :8787, performs real encrypt/decrypt)
  └── Metrics (OpenTelemetry → Prometheus)
  │
  │  HTTPS
  ↓
Azure Key Vault
```

## Data Flow

### Encryption

1. API server sends plaintext to the plugin via gRPC.
2. Plugin base64-encodes the plaintext (using `base64.RawURLEncoding` — no padding, URL-safe alphabet).
3. Plugin calls Azure Key Vault's Encrypt API (RSA-15 for v1, RSA-OAEP-256 for v2).
4. Plugin returns ciphertext plus annotations (algorithm, version, key ID hash) to the API server.
5. API server stores the encrypted data in etcd with prefix `k8s:enc:kms:v1:azurekmsprovider` or `k8s:enc:kms:v2:azurekmsprovider`.

### Decryption

1. API server sends ciphertext plus annotations to the plugin via gRPC.
2. Plugin validates annotations — for v2, algorithm and version must match exactly. Key ID hash is validated to detect key mismatches.
3. Plugin calls Azure Key Vault's Decrypt API.
4. Plugin base64-decodes the result (using `base64.RawURLEncoding`) and returns plaintext to the API server.

### Health Checks

There are two independent health check mechanisms:

- **HTTP `/healthz` endpoint** (port 8787): Performs a full v1 + v2 encrypt/decrypt cycle against Key Vault (4 API calls per invocation). Called by kubelet liveness probes at the interval configured in the static pod spec.
- **KMS v2 Status RPC**: Called by the API server approximately every minute. Performs an encrypt/decrypt cycle (2 API calls per invocation, ~120 Key Vault calls/hour per node from this mechanism alone).

Both verify end-to-end functionality, not just connectivity.

## Authentication

The plugin supports five Azure authentication methods, checked in order:

| Method | Config Requirement | Proxy Support |
|--------|-------------------|---------------|
| Workload Identity | OIDC token + federated credential | No |
| Managed Identity (user-assigned) | `userAssignedIdentityID` in azure.json | No |
| Managed Identity (system-assigned) | `useManagedIdentityExtension: true` | No |
| Service Principal (secret) | `aadClientId` + `aadClientSecret` | Yes |
| Client Certificate | `aadClientId` + `aadClientCertPath` (PKCS#12) | Yes |
| MSI Data Plane Identity | `aadMSIDataPlaneIdentityPath` in azure.json | No |

MSI Data Plane Identity is a downstream-only feature providing UAMI (User Assigned Managed Identity) support for ARO HCP. It uses the `github.com/Azure/msi-dataplane` package.

Only Service Principal and Client Certificate configure a proxy-aware HTTP transport. Proxy mode uses custom headers defined in `pkg/consts/` to route requests through a proxy to Azure AD and Key Vault.

Configuration is read from `/etc/kubernetes/azure.json` (the standard Azure cloud provider config file).

## Deployment

The deployment model depends on the control plane topology:

**HyperShift (hosted control planes):** The plugin runs as a **sidecar container** in the Kube API server pod. The Unix socket is shared between containers via an `emptyDir` volume mount. The control plane operator manages the pod spec and injection of the KMS container.

**Standalone OpenShift:** The plugin is deployed as a **static pod** on each control plane node:

- **Manifest location**: `/etc/kubernetes/manifests/` (managed by kubelet directly)
- **Network**: `hostNetwork: true` (required for Unix socket access)
- **Priority**: `system-node-critical`
- **Security**: Read-only root filesystem, no privilege escalation, all capabilities dropped

The API server references the plugin in its `EncryptionConfiguration` (v1 example shown):

```yaml
resources:
  - resources: [secrets]
    providers:
      - kms:
          name: azurekmsprovider
          endpoint: unix:///opt/azurekms.socket
          cachesize: 1000
```

## Key Rotation

The plugin does **not** support transparent key rotation. Rotation requires a multi-step process:

1. Deploy a second KMS plugin instance with the new key on a different socket.
2. Add both plugins to the encryption configuration (old first).
3. Restart API servers.
4. Swap the order (new plugin first for new encryptions).
5. Restart API servers and re-encrypt all secrets.
6. Remove the old plugin.

This is documented in `docs/rotation.md`.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Dual KMS v1/v2 support | Enables zero-downtime migration from v1 to v2. v2 provides stronger encryption (RSA-OAEP-256 vs RSA-15). |
| Two health check mechanisms | HTTP `/healthz` for kubelet liveness probes; KMS v2 Status RPC for API server health polling. Both do real encrypt/decrypt to guarantee end-to-end functionality. |
| Unix socket over TCP | Better security — no network exposure. Requires static pod deployment with host access. |
| Annotation-based metadata | Stores encryption context (algorithm, key version, key ID hash) alongside ciphertext. Enables validation on decrypt and future extensibility. |
| Static pod (standalone) or sidecar (HyperShift) | In standalone, must run on every control plane node before the API server can start. In HyperShift, runs as a sidecar in the Kube API server pod with a shared Unix socket volume. |
| MSI Data Plane Identity (downstream) | Enables UAMI for ARO HCP where standard Managed Identity is not available. Uses the `msi-dataplane` package for credential acquisition. |

## Dependencies

- **Azure SDK**: `azure-sdk-for-go/sdk/security/keyvault/azkeys` for Key Vault operations, `azidentity` for authentication
- **Azure msi-dataplane**: `github.com/Azure/msi-dataplane` for MSI Data Plane Identity (UAMI, downstream-only)
- **gRPC**: Server framework for KMS protocol
- **k8s.io/kms**: Kubernetes KMS API definitions (v1beta1, v2)
- **OpenTelemetry + Prometheus**: Metrics instrumentation and export
- **mlog**: Structured logging with klog integration

## Testing

- **Unit tests**: In each `pkg/` directory, using mock Key Vault client. Run with `make unit-test`.
- **Integration tests** (`tests/client/`): Require real Azure credentials and Key Vault. Run with `make integration-test`. Note: uses socket path `/opt/azurekms.sock` (differs from default `/opt/azurekms.socket`).
- **E2E tests** (`tests/e2e/`): BATS framework, create kind clusters with the plugin deployed via scripts in `scripts/`. Verify actual secret encryption/decryption in etcd. Separate suites for v1 and v2.
