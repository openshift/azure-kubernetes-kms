// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/kubernetes-kms/pkg/config"
)

var (
	testEnvs       = []string{"", "AZUREPUBLICCLOUD", "AZURECHINACLOUD", "AZUREUSGOVERNMENTCLOUD", "AZUREGERMANCLOUD", "AZUREBLEUCLOUD"}
	vaultDNSSuffix = []string{"vault.azure.net", "vault.azure.net", "vault.azure.cn", "vault.usgovcloudapi.net", "vault.microsoftazure.de", "vault.sovcloud-api.fr"}
)

func TestNewKeyVaultClientError(t *testing.T) {
	tests := []struct {
		desc         string
		config       *config.AzureConfig
		vaultName    string
		keyName      string
		keyVersion   string
		proxyMode    bool
		proxyAddress string
		proxyPort    int
		managedHSM   bool
	}{
		{
			desc:      "vault name not provided",
			config:    &config.AzureConfig{},
			proxyMode: false,
		},
		{
			desc:      "key name not provided",
			config:    &config.AzureConfig{},
			vaultName: "testkv",
			proxyMode: false,
		},
		{
			desc:      "key version not provided",
			config:    &config.AzureConfig{},
			vaultName: "testkv",
			keyName:   "k8s",
			proxyMode: false,
		},
		{
			desc:       "no credentials in config",
			config:     &config.AzureConfig{},
			vaultName:  "testkv",
			keyName:    "key1",
			keyVersion: "262067a9e8ba401aa8a746c5f1a7e147",
		},
		{
			desc:       "unknown azure environment",
			config:     &config.AzureConfig{ClientID: "clientid", ClientSecret: "clientsecret", Cloud: "AzureUnknownCloud"},
			vaultName:  "testkv",
			keyName:    "key1",
			keyVersion: "262067a9e8ba401aa8a746c5f1a7e147",
			managedHSM: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			if _, err := NewKeyVaultClient(test.config, test.vaultName, test.keyName, test.keyVersion, test.proxyMode, test.proxyAddress, test.proxyPort, test.managedHSM); err == nil {
				t.Fatalf("newKeyVaultClient() expected error, got nil")
			}
		})
	}
}

func TestNewKeyVaultClient(t *testing.T) {
	tests := []struct {
		desc             string
		config           *config.AzureConfig
		vaultName        string
		keyName          string
		keyVersion       string
		proxyMode        bool
		proxyAddress     string
		proxyPort        int
		managedHSM       bool
		expectedVaultURL string
	}{
		{
			desc:             "no error",
			config:           &config.AzureConfig{ClientID: "clientid", ClientSecret: "clientsecret", TenantID: "tenantId"},
			vaultName:        "testkv",
			keyName:          "key1",
			keyVersion:       "262067a9e8ba401aa8a746c5f1a7e147",
			proxyMode:        false,
			expectedVaultURL: "https://testkv.vault.azure.net/",
		},
		{
			desc:             "no error with double quotes",
			config:           &config.AzureConfig{ClientID: "clientid", ClientSecret: "clientsecret", TenantID: "tenantId"},
			vaultName:        "\"testkv\"",
			keyName:          "\"key1\"",
			keyVersion:       "\"262067a9e8ba401aa8a746c5f1a7e147\"",
			proxyMode:        false,
			expectedVaultURL: "https://testkv.vault.azure.net/",
		},
		//{
		//	desc:             "no error with proxy mode",
		//	config:           &config.AzureConfig{ClientID: "clientid", ClientSecret: "clientsecret", TenantID: "tenantId"},
		//	vaultName:        "testkv",
		//	keyName:          "key1",
		//	keyVersion:       "262067a9e8ba401aa8a746c5f1a7e147",
		//	proxyMode:        true,
		//	proxyAddress:     "localhost",
		//	proxyPort:        7788,
		//	expectedVaultURL: "http://localhost:7788/testkv.vault.azure.net/",
		//},
		{
			desc:             "no error with managed hsm",
			config:           &config.AzureConfig{ClientID: "clientid", ClientSecret: "clientsecret", TenantID: "tenantId"},
			vaultName:        "testkv",
			keyName:          "key1",
			keyVersion:       "262067a9e8ba401aa8a746c5f1a7e147",
			managedHSM:       true,
			proxyMode:        false,
			expectedVaultURL: "https://testkv.managedhsm.azure.net/",
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			kvClient, err := NewKeyVaultClient(test.config, test.vaultName, test.keyName, test.keyVersion, test.proxyMode, test.proxyAddress, test.proxyPort, test.managedHSM)
			if err != nil {
				t.Fatalf("NewKeyVaultClient() failed with error: %v", err)
			}
			if kvClient == nil {
				t.Fatalf("NewKeyVaultClient() expected kv client to not be nil")
			}
		})
	}
}

func TestKeyVaultClientEncryptKeyIDCasing(t *testing.T) {
	tests := []struct {
		name          string
		vaultURL      string
		responseKeyID string
		expectedError bool
	}{
		{
			name:          "mixed case configured vault matches lowercase response",
			vaultURL:      "https://ExAmPlE.vault.azure.net/",
			responseKeyID: "https://example.vault.azure.net/keys/mykey/abcd",
		},
		{
			name:          "lowercase configured vault matches mixed case response",
			vaultURL:      "https://example.vault.azure.net/",
			responseKeyID: "https://ExAmPlE.vault.azure.net/keys/MyKey/ABCD",
		},
		{
			name:          "different key version is still rejected",
			vaultURL:      "https://ExAmPlE.vault.azure.net/",
			responseKeyID: "https://example.vault.azure.net/keys/mykey/efgh",
			expectedError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			keyIDHash, err := getKeyIDHash(test.vaultURL, "mykey", "abcd")
			if err != nil {
				t.Fatalf("getKeyIDHash() failed: %v", err)
			}

			body, err := json.Marshal(map[string]string{
				"kid":   test.responseKeyID,
				"value": base64.RawURLEncoding.EncodeToString([]byte("ciphertext")),
			})
			if err != nil {
				t.Fatalf("failed to marshal encryption response: %v", err)
			}

			// Mock client that returns our predefined response
			baseClient, err := azkeys.NewClient(test.vaultURL, nil, &azkeys.ClientOptions{
				ClientOptions: azcore.ClientOptions{
					PerCallPolicies: []policy.Policy{policyFunc(func(req *policy.Request) (*http.Response, error) {
						return &http.Response{
							StatusCode: http.StatusOK,
							Header:     http.Header{"Content-Type": []string{"application/json"}},
							Body:       io.NopCloser(bytes.NewReader(body)),
							Request:    req.Raw(),
						}, nil
					})},
				},
			})
			if err != nil {
				t.Fatalf("azkeys.NewClient() failed: %v", err)
			}

			client := &KeyVaultClient{
				baseClient: baseClient,
				keyName:    "mykey",
				keyVersion: "abcd",
				keyIDHash:  keyIDHash,
			}

			result, err := client.Encrypt(context.Background(), []byte("plaintext"), azkeys.EncryptionAlgorithmRSAOAEP256)
			if test.expectedError {
				if err == nil || !strings.Contains(err.Error(), "key id initialized does not match") {
					t.Fatalf("expected key ID mismatch error, got: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}

			const expectedHash = "ec3e6befa79c7dc9a37cac2a8a67cbf0e7fcacdcfc5cf56b463fc80ffdb783f3"
			if result.KeyID != expectedHash {
				t.Errorf("expected key ID hash %s, got %s", expectedHash, result.KeyID)
			}
			if !bytes.Equal(result.Ciphertext, []byte("ciphertext")) {
				t.Errorf("expected ciphertext %q, got %q", "ciphertext", result.Ciphertext)
			}
		})
	}
}

func TestGetVaultURLError(t *testing.T) {
	tests := []struct {
		desc       string
		vaultName  string
		managedHSM bool
	}{
		{
			desc:      "vault name > 24",
			vaultName: "longkeyvaultnamewhichisnotvalid",
		},
		{
			desc:      "vault name < 3",
			vaultName: "kv",
		},
		{
			desc:      "vault name contains non alpha-numeric chars",
			vaultName: "kv_test",
		},
	}

	for _, test := range tests {
		for idx := range testEnvs {
			t.Run(fmt.Sprintf("%s/%s", test.desc, testEnvs[idx]), func(t *testing.T) {
				if _, err := getVaultURL(test.vaultName, test.managedHSM, "AzurePublicCloud"); err == nil {
					t.Fatalf("getVaultURL() expected error, got nil")
				}
			})
		}
	}
}

func TestGetVaultURL(t *testing.T) {
	vaultName := "testkv"

	for idx := range testEnvs {
		t.Run(testEnvs[idx], func(t *testing.T) {
			vaultURL, err := getVaultURL(vaultName, false, testEnvs[idx])
			if err != nil {
				t.Fatalf("expected no error of getting vault URL, got error: %v", err)
			}
			expectedURL := "https://" + vaultName + "." + vaultDNSSuffix[idx] + "/"
			if expectedURL != vaultURL {
				t.Fatalf("expected vault url: %s, got: %s", expectedURL, vaultURL)
			}
		})
	}
}

func TestGetManagedHSMVaultURL(t *testing.T) {
	testCases := []struct {
		name        string
		cloud       string
		expectedURL string
	}{
		{
			name:        "empty cloud defaults to Azure public cloud",
			expectedURL: "https://testhsm.managedhsm.azure.net/",
		},
		{
			name:        "AzureCloud uses the public Managed HSM endpoint",
			cloud:       "AzureCloud",
			expectedURL: "https://testhsm.managedhsm.azure.net/",
		},
		{
			name:        "AzurePublicCloud uses the public Managed HSM endpoint",
			cloud:       "AzurePublicCloud",
			expectedURL: "https://testhsm.managedhsm.azure.net/",
		},
		{
			name:        "AzureGovernmentCloud uses the government Managed HSM endpoint",
			cloud:       "AzureGovernmentCloud",
			expectedURL: "https://testhsm.managedhsm.usgovcloudapi.net/",
		},
		{
			name:        "AzureUSGovernment uses the government Managed HSM endpoint",
			cloud:       "AzureUSGovernment",
			expectedURL: "https://testhsm.managedhsm.usgovcloudapi.net/",
		},
		{
			name:        "AzureUSGovernmentCloud uses the government Managed HSM endpoint",
			cloud:       "AzureUSGovernmentCloud",
			expectedURL: "https://testhsm.managedhsm.usgovcloudapi.net/",
		},
		{
			name:        "AzureChinaCloud uses the China Managed HSM endpoint",
			cloud:       "AzureChinaCloud",
			expectedURL: "https://testhsm.managedhsm.azure.cn/",
		},
		{
			name:        "AzureGermanCloud uses the German Managed HSM endpoint",
			cloud:       "AzureGermanCloud",
			expectedURL: "https://testhsm.managedhsm.microsoftazure.de/",
		},
		{
			name:        "AzureBleuCloud uses the Bleu Managed HSM endpoint",
			cloud:       "AzureBleuCloud",
			expectedURL: "https://testhsm.managedhsm.sovcloud-api.fr/",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			vaultURL, err := getVaultURL("testhsm", true, testCase.cloud)
			if err != nil {
				t.Fatalf("expected no error getting Managed HSM URL, got: %v", err)
			}
			if vaultURL != testCase.expectedURL {
				t.Fatalf("expected Managed HSM URL %q, got %q", testCase.expectedURL, vaultURL)
			}
		})
	}
}

func TestGetAADEndpoint(t *testing.T) {
	testCases := []struct {
		name             string
		cloud            string
		expectedEndpoint string
	}{
		{
			name:             "empty cloud defaults to Azure public cloud",
			expectedEndpoint: "https://login.microsoftonline.com/",
		},
		{
			name:             "AzurePublicCloud uses the public authority",
			cloud:            "AzurePublicCloud",
			expectedEndpoint: "https://login.microsoftonline.com/",
		},
		{
			name:             "AzureChinaCloud uses the China authority",
			cloud:            "AzureChinaCloud",
			expectedEndpoint: "https://login.chinacloudapi.cn/",
		},
		{
			name:             "AzureGovernmentCloud uses the government authority",
			cloud:            "AzureGovernmentCloud",
			expectedEndpoint: "https://login.microsoftonline.us/",
		},
		{
			name:             "AzureUSGovernment uses the government authority",
			cloud:            "AzureUSGovernment",
			expectedEndpoint: "https://login.microsoftonline.us/",
		},
		{
			name:             "AzureUSGovernmentCloud uses the government authority",
			cloud:            "AzureUSGovernmentCloud",
			expectedEndpoint: "https://login.microsoftonline.us/",
		},
		{
			name:             "AzureGermanCloud uses the German authority",
			cloud:            "AzureGermanCloud",
			expectedEndpoint: "https://login.microsoftonline.de/",
		},
		{
			name:             "AzureBleuCloud uses the Bleu authority",
			cloud:            "AzureBleuCloud",
			expectedEndpoint: "https://login.sovcloud-identity.fr/",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			endpoint, err := getAadEndpoint(&config.AzureConfig{Cloud: testCase.cloud}, false, "", 0)
			if err != nil {
				t.Fatalf("expected no error getting AAD endpoint, got: %v", err)
			}
			if endpoint != testCase.expectedEndpoint {
				t.Fatalf("expected AAD endpoint %q, got %q", testCase.expectedEndpoint, endpoint)
			}
		})
	}
}

func TestGetKeyIDHash(t *testing.T) {
	testCases := []struct {
		name                string
		vaultURL            string
		keyName             string
		keyVersion          string
		expectedHash        string
		expectedError       bool
		expectedErrorString string
	}{
		{
			name:          "valid hash, all components have lowercase letters",
			vaultURL:      "https://example.vault.azure.net/",
			keyName:       "mykey",
			keyVersion:    "abcd",
			expectedHash:  "ec3e6befa79c7dc9a37cac2a8a67cbf0e7fcacdcfc5cf56b463fc80ffdb783f3",
			expectedError: false,
		},
		{
			name:          "valid hash, uppercase letters included in key version",
			vaultURL:      "https://example.vault.azure.net/",
			keyName:       "mykey",
			keyVersion:    "EFGH",
			expectedHash:  "cb56e0330a7ccb5e4fc2decddc6293b50478ad2d2d219c1f1b72dc8de2795f23",
			expectedError: false,
		},
		{
			name:                "invalid vault URL",
			vaultURL:            ":invalid-url:",
			keyName:             "mykey",
			keyVersion:          "ABCD",
			expectedHash:        "",
			expectedError:       true,
			expectedErrorString: "failed to parse vault url, error: parse \":invalid-url:\": missing protocol scheme",
		},
		{
			name:                "empty vault name",
			vaultURL:            "",
			keyName:             "mykey",
			keyVersion:          "ABCD",
			expectedHash:        "",
			expectedError:       true,
			expectedErrorString: "vault url, key name and key version cannot be empty",
		},
		{
			name:                "empty key name",
			vaultURL:            "https://example.vault.azure.net/",
			keyName:             "",
			keyVersion:          "ABCD",
			expectedHash:        "",
			expectedError:       true,
			expectedErrorString: "vault url, key name and key version cannot be empty",
		},
		{
			name:                "empty key vesion",
			vaultURL:            "https://example.vault.azure.net/",
			keyName:             "mykey",
			keyVersion:          "",
			expectedHash:        "",
			expectedError:       true,
			expectedErrorString: "vault url, key name and key version cannot be empty",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := getKeyIDHash(tc.vaultURL, tc.keyName, tc.keyVersion)

			if tc.expectedError {
				if (err != nil) && (err.Error() != tc.expectedErrorString) {
					t.Errorf("Expected error: %v, but got: %v", tc.expectedErrorString, err.Error())
				} else if err == nil {
					t.Errorf("Expected error: %v, but didn't get any", tc.expectedErrorString)
				}
			}

			if hash != tc.expectedHash {
				t.Errorf("Expected hash: %s, but got: %s", tc.expectedHash, hash)
			}
		})
	}
}
