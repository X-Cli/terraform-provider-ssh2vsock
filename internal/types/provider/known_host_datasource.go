// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package types

import (
	"context"
	"errors"
	"net"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
)

var (
	ErrUnexpectedAlgorithm = errors.New("unexpected key algorithm")
)

type knownHostHypervisorDataModel struct {
	hostname   string
	port       int
	username   string
	privateKey PrivateKeySpec
	agent      AgentSpec
	knownHost  KnownHostsSpec
	sshfp      SSHFPSpec
}

type knownHostGuestDataModel struct {
	cid  int
	port int
}

type KnownHostModel struct {
	hypervisor    knownHostHypervisorDataModel
	guest         knownHostGuestDataModel
	rsaPubKey     ssh.PublicKey
	ecdsaPubKey   ssh.PublicKey
	ed25519PubKey ssh.PublicKey
}

func KnownHostDatasourceFromTFConfig(ctx context.Context, config tfsdk.Config) (*KnownHostModel, bool, diag.Diagnostics) {
	var dsTFData terraform.KnownHostModel
	if diags := config.Get(ctx, &dsTFData); diags.HasError() {
		return nil, false, diags
	}

	dsHypervisorTFData := dsTFData.Hypervisor
	dsGuestTFData := dsTFData.Guest

	// Checks for unknowns; if some of the essential values are unknown, return that info so that we can communicate/propagate that the computed parameters are currently unknown too!
	if dsHypervisorTFData != nil && (dsHypervisorTFData.Hostname.IsUnknown() ||
		dsHypervisorTFData.Port.IsUnknown() ||
		dsHypervisorTFData.Username.IsUnknown() ||
		dsHypervisorTFData.PrivateKeyPath.IsUnknown() ||
		dsHypervisorTFData.UseAgent.IsUnknown() ||
		dsHypervisorTFData.AgentSockPath.IsUnknown() ||
		dsHypervisorTFData.KnownHosts.IsUnknown() ||
		dsHypervisorTFData.KnownHostsFile.IsUnknown() ||
		dsHypervisorTFData.UseSSHFP.IsUnknown() ||
		dsHypervisorTFData.DNSRecursiveServer.IsUnknown() ||
		dsHypervisorTFData.CAFile.IsUnknown() ||
		dsGuestTFData.CID.IsUnknown() ||
		dsGuestTFData.Port.IsUnknown()) {
		return nil, true, nil
	}

	var knownHostList []string
	if dsHypervisorTFData != nil && !dsHypervisorTFData.KnownHosts.IsNull() {
		knownHostListTF := make([]types.String, 0, len(dsHypervisorTFData.KnownHosts.Elements()))
		if diags := dsHypervisorTFData.KnownHosts.ElementsAs(ctx, &knownHostListTF, true); diags.HasError() {
			return nil, false, diags
		}
		for _, entry := range knownHostListTF {
			if s := entry.ValueString(); s != "" {
				knownHostList = append(knownHostList, s)
			}
		}
	}

	var knownHostHypervisorData knownHostHypervisorDataModel
	if dsHypervisorTFData != nil {
		knownHostHypervisorData = knownHostHypervisorDataModel{
			hostname: dsHypervisorTFData.Hostname.ValueString(),
			port:     int(dsHypervisorTFData.Port.ValueInt32()),
			username: dsHypervisorTFData.Username.ValueString(),
			privateKey: PrivateKeySpec{
				Path:       dsHypervisorTFData.PrivateKeyPath.ValueString(),
				Passphrase: "",
			},
			agent: AgentSpec{
				Use:      dsHypervisorTFData.UseAgent.ValueBool(),
				SockPath: dsHypervisorTFData.AgentSockPath.ValueString(),
			},
			knownHost: KnownHostsSpec{
				List:   knownHostList,
				File:   dsHypervisorTFData.KnownHostsFile.ValueString(),
				Ignore: false,
			},
			sshfp: SSHFPSpec{
				Use:                       dsHypervisorTFData.UseSSHFP.ValueBool(),
				DNSRecursiveServerAddress: dsHypervisorTFData.DNSRecursiveServer.ValueString(),
				CAFile:                    dsHypervisorTFData.CAFile.ValueString(),
			},
		}
	}

	return &KnownHostModel{
		hypervisor: knownHostHypervisorData,
		guest: knownHostGuestDataModel{
			cid:  int(dsGuestTFData.CID.ValueInt32()),
			port: int(dsGuestTFData.Port.ValueInt32()),
		},
	}, false, nil
}

func (ds *KnownHostModel) MergeProviderData(ctx context.Context, providerData *terraform.ProviderDataModel) (bool, diag.Diagnostics) {
	if providerData == nil || providerData.Hypervisor == nil {
		return false, nil
	}

	if ds.hypervisor.hostname == "" {
		if providerData.Hypervisor.Hostname.IsUnknown() {
			return true, nil
		}
		ds.hypervisor.hostname = providerData.Hypervisor.Hostname.ValueString()
	}
	if ds.hypervisor.port == 0 {
		if providerData.Hypervisor.Port.IsUnknown() {
			return true, nil
		}
		ds.hypervisor.port = int(providerData.Hypervisor.Port.ValueInt32())
	}
	if ds.hypervisor.username == "" {
		if providerData.Hypervisor.Username.IsUnknown() {
			return true, nil
		}
		ds.hypervisor.username = providerData.Hypervisor.Username.ValueString()
	}

	// Grouping the authentication mechanisms because it would not make sense to copy some data from the provider if some data are defined in the datasource itself; it's all or nothing
	if ds.hypervisor.privateKey.Path == "" && !ds.hypervisor.agent.Use {
		if providerData.Hypervisor.Password.IsUnknown() ||
			providerData.Hypervisor.PrivateKeyPath.IsUnknown() ||
			providerData.Hypervisor.PrivateKeyPassphrase.IsUnknown() ||
			providerData.Hypervisor.UseAgent.IsUnknown() ||
			providerData.Hypervisor.AgentSockPath.IsUnknown() {
			return true, nil
		}

		ds.hypervisor.privateKey.Path = providerData.Hypervisor.PrivateKeyPath.ValueString()
		ds.hypervisor.privateKey.Passphrase = providerData.Hypervisor.PrivateKeyPassphrase.ValueString()
		ds.hypervisor.agent.Use = providerData.Hypervisor.UseAgent.ValueBool()
		ds.hypervisor.agent.SockPath = providerData.Hypervisor.AgentSockPath.ValueString()
	}

	// Here again, it's all or nothing regarding host key authenticatin copying from provider data
	if len(ds.hypervisor.knownHost.List) == 0 && ds.hypervisor.knownHost.File == "" && !ds.hypervisor.sshfp.Use {
		if providerData.Hypervisor.KnownHosts.IsUnknown() ||
			providerData.Hypervisor.KnownHostsFile.IsUnknown() ||
			providerData.Hypervisor.UseSSHFP.IsUnknown() ||
			providerData.Hypervisor.DNSRecursiveServer.IsUnknown() ||
			providerData.Hypervisor.CAFile.IsUnknown() {
			return true, nil
		}

		var providerRawKnownHosts []string
		if !providerData.Hypervisor.KnownHosts.IsNull() {
			hypervisorRawKnownHostsTF := make([]types.String, 0, len(providerData.Hypervisor.KnownHosts.Elements()))
			if diags := providerData.Hypervisor.KnownHosts.ElementsAs(ctx, &hypervisorRawKnownHostsTF, true); diags.HasError() {
				return false, diags
			}
			for _, entry := range hypervisorRawKnownHostsTF {
				if s := entry.ValueString(); s != "" {
					providerRawKnownHosts = append(providerRawKnownHosts, s)
				}
			}
		}

		ds.hypervisor.knownHost.List = providerRawKnownHosts
		ds.hypervisor.knownHost.File = providerData.Hypervisor.KnownHostsFile.ValueString()
		ds.hypervisor.sshfp.Use = providerData.Hypervisor.UseSSHFP.ValueBool()
		ds.hypervisor.sshfp.DNSRecursiveServerAddress = providerData.Hypervisor.DNSRecursiveServer.ValueString()
		ds.hypervisor.sshfp.CAFile = providerData.Hypervisor.CAFile.ValueString()
	}
	return false, nil
}

func (ds *KnownHostModel) HypervisorHostname() string {
	return ds.hypervisor.hostname
}

func (ds *KnownHostModel) HypervisorPort() int {
	if ds.hypervisor.port != 0 {
		return ds.hypervisor.port
	}
	return 22
}

func (ds *KnownHostModel) GuestPort() int {
	if ds.guest.port != 0 {
		return ds.guest.port
	}
	return 22
}

func (ds *KnownHostModel) GuestCID() int {
	return ds.guest.cid
}

func (ds *KnownHostModel) HypervisorUsername() string {
	if ds.hypervisor.username != "" {
		return ds.hypervisor.username
	}
	return "root"
}

func (ds *KnownHostModel) GuestUsername() string {
	return "root"
}

func (ds *KnownHostModel) HypervisorAcceptedAlgorithms(ctx context.Context) ([]string, error) {
	return getAcceptedAlgorithms(ctx, ds.hypervisor.hostname, ds.HypervisorPort(), ds.hypervisor.knownHost.List, ds.hypervisor.knownHost.File, ds.hypervisor.sshfp)
}

func (ds *KnownHostModel) GuestAcceptedAlgorithms(ctx context.Context) ([]string, error) {
	return nil, nil
}

func (ds *KnownHostModel) HypervisorHostKeyCallback(ctx context.Context) (ssh.HostKeyCallback, error) {
	pubKeys, err := getPubKeys(ds.hypervisor.hostname, ds.HypervisorPort(), ds.hypervisor.knownHost.List, ds.hypervisor.knownHost.File)
	if err != nil {
		return nil, err
	}
	return verifyKeys(ctx, ds.hypervisor.hostname, ds.hypervisor.sshfp, pubKeys), nil
}

func (ds *KnownHostModel) GuestHostKeyCallback(_ context.Context) (ssh.HostKeyCallback, error) {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		switch key.Type() {
		case ssh.KeyAlgoRSA:
			ds.rsaPubKey = key
		case ssh.KeyAlgoECDSA256:
			fallthrough
		case ssh.KeyAlgoECDSA384:
			fallthrough
		case ssh.KeyAlgoECDSA521:
			ds.ecdsaPubKey = key
		case ssh.KeyAlgoED25519:
			ds.ed25519PubKey = key
		default:
			return ErrUnexpectedAlgorithm
		}
		return nil
	}, nil
}

func (ds *KnownHostModel) HypervisorAuthMethod() (ssh.AuthMethod, error) {
	if ds.hypervisor.agent.Use {
		return getAuthMethodFromAgent(ds.hypervisor.agent.SockPath)
	}
	if ds.hypervisor.privateKey.Path != "" {
		return getAuthMethodFromPrivateKey(ds.hypervisor.privateKey)
	}
	return nil, ErrNoAuthnMethodDefined
}

func (ds *KnownHostModel) GuestAuthMethod() (ssh.AuthMethod, error) {
	return nil, nil
}

func (ds *KnownHostModel) GuestPublicKey(keyType string) ssh.PublicKey {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return ds.rsaPubKey
	case ssh.KeyAlgoECDSA256:
		fallthrough
	case ssh.KeyAlgoECDSA384:
		fallthrough
	case ssh.KeyAlgoRSASHA512:
		return ds.ecdsaPubKey
	case ssh.KeyAlgoED25519:
		return ds.ed25519PubKey
	default:
		return nil
	}
}

// ValidateConfig is called during the Read call on the data source to validate configuration validity and consistency with all available data, including provider configuration
func (ds *KnownHostModel) ValidateConfig() diag.Diagnostics {
	if ds.hypervisor.hostname == "" {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: hostname is not set; it must be configured at least once either in the provider configuration or the data source configuration",
			),
		}
	}
	// Port is not checked because the port defaults to 22 if not defined
	// Username is not checked because the username defaults to "root" if not defined
	if !ds.hypervisor.agent.Use && ds.hypervisor.privateKey.Path == "" {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: at least one authentication method for the hypervisor must be defined; none were provided either in the provider configuration or the data source configuration",
			),
		}
	}
	if len(ds.hypervisor.knownHost.List) == 0 && ds.hypervisor.knownHost.File == "" && !ds.hypervisor.sshfp.Use {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: at least one known host entry for the hypervisor must be defined; none were provided either in the provider configuration or the data source configuration",
			),
		}
	}

	// The hostname being a domain name is tested by checking that the hostname cannot be parsed as an IP address, because domain names have such large acceptance criteria that, strictly speaking, an IP address is a valid domain name...
	parsedHostname := net.ParseIP(ds.hypervisor.hostname)
	if ds.hypervisor.sshfp.Use && parsedHostname != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: host verification is done by querying the DNS for SSHFP records, but the hostname is an IP address and not a domain name",
			),
		}
	}

	return nil
}
