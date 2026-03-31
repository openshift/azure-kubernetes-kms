package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
	"monis.app/mlog"
)

// AzureConfig is representing /etc/kubernetes/azure.json.
type AzureConfig struct {
	Cloud                       string `json:"cloud" yaml:"cloud"`
	TenantID                    string `json:"tenantId" yaml:"tenantId"`
	ClientID                    string `json:"aadClientId" yaml:"aadClientId"`
	ClientSecret                string `json:"aadClientSecret" yaml:"aadClientSecret"`
	UseManagedIdentityExtension bool   `json:"useManagedIdentityExtension,omitempty" yaml:"useManagedIdentityExtension,omitempty"`
	UserAssignedIdentityID      string `json:"userAssignedIdentityID,omitempty" yaml:"userAssignedIdentityID,omitempty"`
	AADClientCertPath           string `json:"aadClientCertPath" yaml:"aadClientCertPath"`
	AADClientCertPassword       string `json:"aadClientCertPassword" yaml:"aadClientCertPassword"`
	AADMSIDataPlaneIdentityPath string `json:"aadMSIDataPlaneIdentityPath,omitempty" yaml:"aadMSIDataPlaneIdentityPath,omitempty"`

	// UseFederatedWorkloadIdentityExtension enables workload identity authentication
	// using a federated token projected into the pod. When enabled, AADClientID and
	// AADFederatedTokenFile must also be set.
	UseFederatedWorkloadIdentityExtension bool   `json:"useFederatedWorkloadIdentityExtension,omitempty" yaml:"useFederatedWorkloadIdentityExtension,omitempty"`
	AADClientID                           string `json:"aadClientID,omitempty" yaml:"aadClientID,omitempty"`
	AADFederatedTokenFile                 string `json:"aadFederatedTokenFile,omitempty" yaml:"aadFederatedTokenFile,omitempty"`
}

// GetAzureConfig returns configs in the azure.json cloud provider file.
func GetAzureConfig(configFile string) (config *AzureConfig, err error) {
	cfg := AzureConfig{}

	mlog.Trace("populating AzureConfig from config file", "configFile", configFile)
	bytes, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file %s, error: %+v", configFile, err)
	}
	if err = yaml.Unmarshal(bytes, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal azure.json, error: %+v", err)
	}
	return &cfg, nil
}
