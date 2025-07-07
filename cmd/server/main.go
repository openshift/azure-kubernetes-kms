// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/kubernetes-kms/pkg/config"
	"github.com/Azure/kubernetes-kms/pkg/metrics"
	"github.com/Azure/kubernetes-kms/pkg/plugin"
	"github.com/Azure/kubernetes-kms/pkg/plugin/aes"
	"github.com/Azure/kubernetes-kms/pkg/utils"
	"github.com/Azure/kubernetes-kms/pkg/version"

	"google.golang.org/grpc"
	"k8s.io/klog/v2"
	kmsv1 "k8s.io/kms/apis/v1beta1"
	kmsv2 "k8s.io/kms/apis/v2"
	"k8s.io/kms/pkg/service"
	"monis.app/mlog"
)

var (
	listenAddr    = flag.String("listen-addr", "unix:///opt/azurekms.socket", "gRPC listen address")
	keyvaultName  = flag.String("keyvault-name", "", "Azure Key Vault name")
	keyName       = flag.String("key-name", "", "Azure Key Vault KMS key name")
	keyVersion    = flag.String("key-version", "", "Azure Key Vault KMS key version")
	managedHSM    = flag.Bool("managed-hsm", false, "Azure Key Vault Managed HSM. Refer to https://docs.microsoft.com/en-us/azure/key-vault/managed-hsm/overview for more details.")
	logFormatJSON = flag.Bool("log-format-json", false, "set log formatter to json")
	logLevel      = flag.Int("v", 0, "In order of increasing verbosity: 0=warning/error, 2=info, 4=debug, 6=trace, 10=all")
	// TODO remove this flag in future release.
	_              = flag.String("configFilePath", "/etc/kubernetes/azure.json", "[DEPRECATED] Path for Azure Cloud Provider config file")
	configFilePath = flag.String("config-file-path", "/etc/kubernetes/azure.json", "Path for Azure Cloud Provider config file")
	versionInfo    = flag.Bool("version", false, "Prints the version information")

	healthzPort    = flag.Int("healthz-port", 8787, "port for health check")
	healthzPath    = flag.String("healthz-path", "/healthz", "path for health check")
	healthzTimeout = flag.Duration("healthz-timeout", 20*time.Second, "RPC timeout for health check")
	metricsBackend = flag.String("metrics-backend", "prometheus", "Backend used for metrics")
	metricsAddress = flag.String("metrics-addr", "8095", "The address the metric endpoint binds to")

	proxyMode    = flag.Bool("proxy-mode", false, "Proxy mode")
	proxyAddress = flag.String("proxy-address", "", "proxy address")
	proxyPort    = flag.Int("proxy-port", 7788, "port for proxy")

	encryptedClusterSeedFile     = flag.String("encrypted-cluster-seed-file", "", "File with encrypted cluster seed used to generate KEKs to encrypt API server DEK seeds")
	generateEncryptedClusterSeed = flag.String("generate-encrypted-cluster-seed-file", "", "File to write encrypted cluster seed")
)

func main() {
	if err := setupKMSPlugin(); err != nil {
		mlog.Fatal(err)
	}
}

func setupKMSPlugin() error {
	defer mlog.Setup()() // set up log flushing and attempt to flush on exit
	flag.Parse()
	ctx := withShutdownSignal(context.Background())

	logFormat := mlog.FormatText
	if *logFormatJSON {
		logFormat = mlog.FormatJSON
	}

	if err := mlog.ValidateAndSetKlogLevelAndFormatGlobally(ctx, klog.Level(*logLevel), logFormat); err != nil {
		return fmt.Errorf("invalid --log-level set: %w", err)
	}

	if *versionInfo {
		if err := version.PrintVersion(); err != nil {
			return fmt.Errorf("failed to print version: %w", err)
		}
		return nil
	}

	// initialize metrics exporter
	err := metrics.InitMetricsExporter(*metricsBackend, *metricsAddress)
	if err != nil {
		return fmt.Errorf("failed to initialize metrics exporter: %w", err)
	}

	mlog.Always("Starting KeyManagementServiceServer service", "version", version.BuildVersion, "buildDate", version.BuildDate)

	pluginConfig := &plugin.Config{
		KeyVaultName:   *keyvaultName,
		KeyName:        *keyName,
		KeyVersion:     *keyVersion,
		ManagedHSM:     *managedHSM,
		ProxyMode:      *proxyMode,
		ProxyAddress:   *proxyAddress,
		ProxyPort:      *proxyPort,
		ConfigFilePath: *configFilePath,
	}

	azureConfig, err := config.GetAzureConfig(pluginConfig.ConfigFilePath)
	if err != nil {
		return fmt.Errorf("failed to get azure config: %w", err)
	}

	kvClient, err := plugin.NewKeyVaultClient(
		azureConfig,
		pluginConfig.KeyVaultName,
		pluginConfig.KeyName,
		pluginConfig.KeyVersion,
		pluginConfig.ProxyMode,
		pluginConfig.ProxyAddress,
		pluginConfig.ProxyPort,
		pluginConfig.ManagedHSM,
	)
	if err != nil {
		return fmt.Errorf("failed to create key vault client: %w", err)
	}

	if len(*generateEncryptedClusterSeed) != 0 {
		clusterSeed, err := aes.GenerateKey(sha256.BlockSize) // larger seeds will be hashed down to this size
		if err != nil {
			return fmt.Errorf("failed to generate cluster seed: %w", err)
		}

		ctx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()

		encryptedClusterSeedResp, err := kvClient.Encrypt(ctx, clusterSeed, azkeys.EncryptionAlgorithmRSAOAEP256)
		if err != nil {
			return fmt.Errorf("failed to encrypt cluster seed: %w", err)
		}

		encryptedClusterSeedResp.Annotations["created-at.azure.akv.io"] = []byte(time.Now().Format(time.RFC3339))
		encryptedClusterSeedResp.Annotations["vault-name.azure.akv.io"] = []byte(*keyvaultName)
		encryptedClusterSeedResp.Annotations["key-name.azure.akv.io"] = []byte(*keyName)
		encryptedClusterSeedResp.Annotations["key-version.azure.akv.io"] = []byte(*keyVersion)

		// Store the complete response as JSON
		jsonData, err := json.MarshalIndent(encryptedClusterSeedResp, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal encrypt response: %w", err)
		}

		if err := os.WriteFile(*generateEncryptedClusterSeed, jsonData, 0o600); err != nil {
			return fmt.Errorf("failed to write cluster seed file: %w", err)
		}

		return nil
	}

	// Initialize and run the GRPC server
	proto, addr, err := utils.ParseEndpoint(*listenAddr)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}
	if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove socket file %s: %w", addr, err)
	}

	listener, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("failed to listen addr: %s, proto: %s: %w", addr, proto, err)
	}

	opts := []grpc.ServerOption{
		grpc.UnaryInterceptor(utils.UnaryServerInterceptor),
	}

	s := grpc.NewServer(opts...)

	// legacy path
	if len(*encryptedClusterSeedFile) == 0 {
		// register kms v1 server
		kmsV1Server, err := plugin.NewKMSv1Server(kvClient)
		if err != nil {
			return fmt.Errorf("failed to create server: %w", err)
		}
		kmsv1.RegisterKeyManagementServiceServer(s, kmsV1Server)

		// register kms v2 server
		kmsV2Server, err := plugin.NewKMSv2Server(kvClient)
		if err != nil {
			return fmt.Errorf("failed to create kms V2 server: %w", err)
		}
		kmsv2.RegisterKeyManagementServiceServer(s, kmsV2Server)

		// Health check for kms v1 and v2
		healthz := &plugin.HealthZ{
			KMSv1Server: kmsV1Server,
			KMSv2Server: kmsV2Server,
			HealthCheckURL: &url.URL{
				Host: net.JoinHostPort("", strconv.FormatUint(uint64(*healthzPort), 10)),
				Path: *healthzPath,
			},
			UnixSocketPath: listener.Addr().String(),
			RPCTimeout:     *healthzTimeout,
		}
		go healthz.Serve()
	} else {
		fileData, err := os.ReadFile(*encryptedClusterSeedFile)
		if err != nil {
			return fmt.Errorf("failed to read encrypted cluster seed file: %w", err)
		}

		// Try to parse as JSON format (service.EncryptResponse) first
		var encryptResp service.EncryptResponse
		var clusterSeed []byte

		if jsonErr := json.Unmarshal(fileData, &encryptResp); jsonErr == nil {
			mlog.Info("Using encrypted cluster seed file")

			// Extract metadata from annotations
			storedVaultName := string(encryptResp.Annotations["vault-name.azure.akv.io"])
			storedKeyName := string(encryptResp.Annotations["key-name.azure.akv.io"])
			storedKeyVersion := string(encryptResp.Annotations["key-version.azure.akv.io"])

			// Validation
			if storedVaultName != *keyvaultName {
				return fmt.Errorf("key vault name mismatch: stored=%s, current=%s", storedVaultName, *keyvaultName)
			}
			if storedKeyName != *keyName {
				return fmt.Errorf("key name mismatch: stored=%s, current=%s", storedKeyName, *keyName)
			}
			if storedKeyVersion != *keyVersion {
				return fmt.Errorf("key version mismatch: stored=%s, current=%s", storedKeyVersion, *keyVersion)
			}

			ctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()

			// Use the stored response data for decryption
			clusterSeed, err = kvClient.Decrypt(ctx, encryptResp.Ciphertext, azkeys.EncryptionAlgorithmRSAOAEP256, "", encryptResp.Annotations, encryptResp.KeyID)
			if err != nil {
				return fmt.Errorf("failed to decrypt cluster seed (production format): %w", err)
			}

			mlog.Always("Successfully decrypted cluster seed",
				"keyVault", storedVaultName,
				"keyName", storedKeyName,
				"keyVersion", storedKeyVersion,
				"keyID", encryptResp.KeyID)
		}

		kmsV2ServerWrapped, err := plugin.NewKMSv2ServerWrapped(clusterSeed)
		if err != nil {
			return fmt.Errorf("failed to create kms V2 server: %w", err)
		}
		kmsv2.RegisterKeyManagementServiceServer(s, kmsV2ServerWrapped)

		healthCheckURL := &url.URL{
			Host: net.JoinHostPort("", strconv.FormatUint(uint64(*healthzPort), 10)),
			Path: *healthzPath,
		}

		// if we bootstrap, we are always healthy because the crypto is all local
		go plugin.BlockingRunAlwaysHealthyServer(healthCheckURL)
	}

	mlog.Always("Listening for connections", "addr", listener.Addr().String())
	go func() {
		if err := s.Serve(listener); err != nil {
			mlog.Fatal(fmt.Errorf("failed to serve kms server: %w", err))
		}
	}()

	<-ctx.Done()
	// gracefully stop the grpc server
	mlog.Always("terminating the server")
	s.GracefulStop()

	return nil
}

// withShutdownSignal returns a copy of the parent context that will close if
// the process receives termination signals.
func withShutdownSignal(ctx context.Context) context.Context {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT, os.Interrupt)

	nctx, cancel := context.WithCancel(ctx)

	go func() {
		<-signalChan
		mlog.Always("received shutdown signal")
		cancel()
	}()
	return nctx
}
