// Copyright (c) Microsoft and contributors.  All rights reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

package plugin

import (
	"fmt"
	"testing"

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
			name:          "valid hash",
			vaultURL:      "https://example.vault.azure.net/",
			keyName:       "mykey",
			keyVersion:    "ABCD",
			expectedHash:  "567d783db3043fe298fe0d9eeedb0029a3815cdd4fe4b059d018c91e6acffe3b",
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
