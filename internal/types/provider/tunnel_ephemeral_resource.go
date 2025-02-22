// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package types

import (
	"context"
	"net"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/hostkeychecking"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshfp"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
)

type HypervisorEphemeralTunnelResourceData struct {
	hostname   string
	port       int
	username   string
	password   string
	privateKey PrivateKeySpec
	agent      AgentSpec
	knownHost  KnownHostsSpec
	sshfp      SSHFPSpec
}

type GuestEpehemeralTunnelResourceData struct {
	cid        int
	hostname   string
	port       int
	username   string
	password   string
	privateKey PrivateKeySpec
	agent      AgentSpec
	knownHost  KnownHostsSpec
	sshfp      SSHFPSpec
}

type EphemeralTunnelResourceData struct {
	hypervisor HypervisorEphemeralTunnelResourceData
	guest      GuestEpehemeralTunnelResourceData
}

func TunnelEphemeralResourceFromTFConfig(ctx context.Context, config tfsdk.Config) (*EphemeralTunnelResourceData, bool, diag.Diagnostics) {
	var resourceConfig terraform.EphemeralTunnelResourceDataModel
	if diags := config.Get(ctx, &resourceConfig); diags.HasError() {
		return nil, false, diags
	}
	hypervisorTFModel := resourceConfig.Hypervisor
	guestTFModel := resourceConfig.Guest

	if hypervisorTFModel != nil &&
		(hypervisorTFModel.Hostname.IsUnknown() ||
			hypervisorTFModel.Port.IsUnknown() ||
			hypervisorTFModel.Username.IsUnknown() ||
			hypervisorTFModel.Password.IsUnknown() ||
			hypervisorTFModel.PrivateKeyPath.IsUnknown() ||
			hypervisorTFModel.PrivateKeyPassphrase.IsUnknown() ||
			hypervisorTFModel.UseAgent.IsUnknown() ||
			hypervisorTFModel.AgentSockPath.IsUnknown() ||
			hypervisorTFModel.KnownHosts.IsUnknown() ||
			hypervisorTFModel.KnownHostsFile.IsUnknown() ||
			hypervisorTFModel.UseSSHFP.IsUnknown() ||
			hypervisorTFModel.DNSRecursiveServer.IsUnknown() ||
			hypervisorTFModel.CAFile.IsUnknown() ||
			guestTFModel.CID.IsUnknown() ||
			guestTFModel.Port.IsUnknown() ||
			guestTFModel.Hostname.IsUnknown() ||
			guestTFModel.Username.IsUnknown() ||
			guestTFModel.Password.IsUnknown() ||
			guestTFModel.PrivateKeyPath.IsUnknown() ||
			guestTFModel.PrivateKeyPassphrase.IsUnknown() ||
			guestTFModel.UseAgent.IsUnknown() ||
			guestTFModel.AgentSockPath.IsUnknown() ||
			guestTFModel.KnownHosts.IsUnknown() ||
			guestTFModel.KnownHostsFile.IsUnknown() ||
			guestTFModel.IgnoreHostKey.IsUnknown() ||
			guestTFModel.UseSSHFP.IsUnknown() ||
			guestTFModel.DNSRecursiveServer.IsUnknown() ||
			guestTFModel.CAFile.IsUnknown()) {
		return nil, true, nil
	}

	var hypervisorRawKnownHosts []string
	if hypervisorTFModel != nil && !hypervisorTFModel.KnownHosts.IsNull() {
		hypervisorRawKnownHostsTF := make([]types.String, 0, len(hypervisorTFModel.KnownHosts.Elements()))
		if diags := hypervisorTFModel.KnownHosts.ElementsAs(ctx, &hypervisorRawKnownHostsTF, true); diags.HasError() {
			return nil, false, diags
		}
		for _, entry := range hypervisorRawKnownHostsTF {
			if s := entry.ValueString(); s != "" {
				hypervisorRawKnownHosts = append(hypervisorRawKnownHosts, s)
			}
		}
	}

	var guestRawKnownHosts []string
	if !guestTFModel.KnownHosts.IsNull() {
		guestRawKnownHostsTF := make([]types.String, 0, len(guestTFModel.KnownHosts.Elements()))
		if diags := guestTFModel.KnownHosts.ElementsAs(ctx, &guestRawKnownHostsTF, true); diags.HasError() {
			return nil, false, diags
		}
		for _, entry := range guestRawKnownHostsTF {
			if s := entry.ValueString(); s != "" {
				guestRawKnownHosts = append(guestRawKnownHosts, s)
			}
		}
	}

	var hypervisorResourceData HypervisorEphemeralTunnelResourceData
	if hypervisorTFModel != nil {
		hypervisorResourceData = HypervisorEphemeralTunnelResourceData{
			hostname: hypervisorTFModel.Hostname.ValueString(),
			port:     int(hypervisorTFModel.Port.ValueInt32()),
			username: hypervisorTFModel.Username.ValueString(),
			password: hypervisorTFModel.Password.ValueString(),
			privateKey: PrivateKeySpec{
				Path:       hypervisorTFModel.PrivateKeyPath.ValueString(),
				Passphrase: hypervisorTFModel.PrivateKeyPassphrase.ValueString(),
			},
			agent: AgentSpec{
				Use:      hypervisorTFModel.UseAgent.ValueBool(),
				SockPath: hypervisorTFModel.AgentSockPath.ValueString(),
			},
			knownHost: KnownHostsSpec{
				List:   hypervisorRawKnownHosts,
				File:   hypervisorTFModel.KnownHostsFile.ValueString(),
				Ignore: false,
			},
			sshfp: SSHFPSpec{
				Use:                       hypervisorTFModel.UseSSHFP.ValueBool(),
				DNSRecursiveServerAddress: hypervisorTFModel.DNSRecursiveServer.ValueString(),
				CAFile:                    hypervisorTFModel.CAFile.ValueString(),
			},
		}
	}

	return &EphemeralTunnelResourceData{
		hypervisor: hypervisorResourceData,
		guest: GuestEpehemeralTunnelResourceData{
			cid:      int(guestTFModel.CID.ValueInt32()),
			hostname: guestTFModel.Hostname.ValueString(),
			port:     int(guestTFModel.Port.ValueInt32()),
			username: guestTFModel.Username.ValueString(),
			password: guestTFModel.Password.ValueString(),
			privateKey: PrivateKeySpec{
				Path:       guestTFModel.PrivateKeyPath.ValueString(),
				Passphrase: guestTFModel.PrivateKeyPassphrase.ValueString(),
			},
			agent: AgentSpec{
				Use:      guestTFModel.UseAgent.ValueBool(),
				SockPath: guestTFModel.AgentSockPath.ValueString(),
			},
			knownHost: KnownHostsSpec{
				List:   guestRawKnownHosts,
				File:   guestTFModel.KnownHostsFile.ValueString(),
				Ignore: guestTFModel.IgnoreHostKey.ValueBool(),
			},
			sshfp: SSHFPSpec{
				Use:                       guestTFModel.UseSSHFP.ValueBool(),
				DNSRecursiveServerAddress: guestTFModel.DNSRecursiveServer.ValueString(),
				CAFile:                    guestTFModel.CAFile.ValueString(),
			},
		},
	}, false, nil
}

func (d *EphemeralTunnelResourceData) MergeProviderData(ctx context.Context, providerData *terraform.ProviderDataModel) (bool, diag.Diagnostics) {
	if providerData == nil || providerData.Hypervisor == nil {
		return false, nil
	}

	if d.hypervisor.hostname == "" {
		if providerData.Hypervisor.Hostname.IsUnknown() {
			return true, nil
		}
		d.hypervisor.hostname = providerData.Hypervisor.Hostname.ValueString()
	}
	if d.hypervisor.port == 0 {
		if providerData.Hypervisor.Port.IsUnknown() {
			return true, nil
		}
		d.hypervisor.port = int(providerData.Hypervisor.Port.ValueInt32())
	}
	if d.hypervisor.username == "" {
		if providerData.Hypervisor.Username.IsUnknown() {
			return true, nil
		}
		d.hypervisor.username = providerData.Hypervisor.Username.ValueString()
	}

	// Grouping the authentication mechanisms because it would not make sense to copy some data from the provider if some data are defined in the datasource itself; it's all or nothing
	if d.hypervisor.password == "" && d.hypervisor.privateKey.Path == "" && !d.hypervisor.agent.Use {
		if providerData.Hypervisor.Password.IsUnknown() ||
			providerData.Hypervisor.PrivateKeyPath.IsUnknown() ||
			providerData.Hypervisor.PrivateKeyPassphrase.IsUnknown() ||
			providerData.Hypervisor.UseAgent.IsUnknown() ||
			providerData.Hypervisor.AgentSockPath.IsUnknown() {
			return true, nil
		}
		d.hypervisor.password = providerData.Hypervisor.Password.ValueString()
		d.hypervisor.privateKey.Path = providerData.Hypervisor.PrivateKeyPath.ValueString()
		d.hypervisor.privateKey.Passphrase = providerData.Hypervisor.PrivateKeyPassphrase.ValueString()
		d.hypervisor.agent.Use = providerData.Hypervisor.UseAgent.ValueBool()
		d.hypervisor.agent.SockPath = providerData.Hypervisor.AgentSockPath.ValueString()
	}

	// Here again, it's all or nothing regarding host key authentification copying from provider data
	if len(d.hypervisor.knownHost.List) == 0 && d.hypervisor.knownHost.File == "" && !d.hypervisor.sshfp.Use {
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
		d.hypervisor.knownHost.List = providerRawKnownHosts
		d.hypervisor.knownHost.File = providerData.Hypervisor.KnownHostsFile.ValueString()
		d.hypervisor.sshfp.Use = providerData.Hypervisor.UseSSHFP.ValueBool()
		d.hypervisor.sshfp.DNSRecursiveServerAddress = providerData.Hypervisor.DNSRecursiveServer.ValueString()
		d.hypervisor.sshfp.CAFile = providerData.Hypervisor.CAFile.ValueString()
	}
	return false, nil
}

func (d *EphemeralTunnelResourceData) GuestCID() int {
	return d.guest.cid
}

func (d *EphemeralTunnelResourceData) HypervisorHostname() string {
	return d.hypervisor.hostname
}

func (d *EphemeralTunnelResourceData) GuestHostname() string {
	return d.guest.hostname
}

func (d *EphemeralTunnelResourceData) HypervisorPort() int {
	if d.hypervisor.port != 0 {
		return d.hypervisor.port
	}
	return 22
}

func (d *EphemeralTunnelResourceData) GuestPort() int {
	if d.guest.port != 0 {
		return d.guest.port
	}
	if d.hypervisor.port != 0 {
		return d.hypervisor.port
	}
	return 22
}

func (d *EphemeralTunnelResourceData) HypervisorUsername() string {
	if d.hypervisor.username != "" {
		return d.hypervisor.username
	}
	return "root"
}

func (d *EphemeralTunnelResourceData) GuestUsername() string {
	if d.guest.username != "" {
		return d.guest.username
	}
	if d.hypervisor.username != "" {
		return d.hypervisor.username
	}
	return "root"
}

func (d *EphemeralTunnelResourceData) HypervisorAuthMethod() (ssh.AuthMethod, error) {
	if d.hypervisor.agent.Use {
		return getAuthMethodFromAgent(d.hypervisor.agent.SockPath)
	}
	if d.hypervisor.privateKey.Path != "" {
		return getAuthMethodFromPrivateKey(d.hypervisor.privateKey)
	}
	if d.hypervisor.password != "" {
		return ssh.Password(d.hypervisor.password), nil
	}
	return nil, ErrNoAuthnMethodDefined
}

func (d *EphemeralTunnelResourceData) GuestAuthMethod() (ssh.AuthMethod, error) {
	if d.guest.agent.Use || (d.hypervisor.agent.Use && d.guest.privateKey.Path == "" && d.guest.password == "") {
		// Only falling back on the hypervisor agent variable if absolutely no authentication method is defined on the resource
		sockPath := d.guest.agent.SockPath
		if sockPath == "" {
			sockPath = d.hypervisor.agent.SockPath
		}
		return getAuthMethodFromAgent(sockPath)
	}
	if d.guest.privateKey.Path != "" || (d.hypervisor.privateKey.Path != "" && d.guest.password == "") {
		// Falling back on the hypervisor path if no password was defined on the resource, because only on auth method can be defined and if password is defined, then the practionner did not meant to fallback on the hypervisor method
		pkSpec := d.guest.privateKey
		if pkSpec.Path == "" {
			pkSpec = d.hypervisor.privateKey
		}
		return getAuthMethodFromPrivateKey(pkSpec)
	}
	if d.guest.password != "" {
		// Not falling back on the hypervisor password because it would not make any sense security-wise to set the same password on the hypervisor and on one of its guests!
		return ssh.Password(d.guest.password), nil
	}
	return nil, ErrNoAuthnMethodDefined
}

func (d *EphemeralTunnelResourceData) HypervisorHostKeyCallback(ctx context.Context) (ssh.HostKeyCallback, error) {
	pubKeys, err := getPubKeys(d.hypervisor.hostname, d.HypervisorPort(), d.hypervisor.knownHost.List, d.hypervisor.knownHost.File)
	if err != nil {
		return nil, err
	}

	return verifyKeys(ctx, d.hypervisor.hostname, d.hypervisor.sshfp, pubKeys), nil
}

func (d *EphemeralTunnelResourceData) GuestHostKeyCallback(ctx context.Context) (ssh.HostKeyCallback, error) {
	if d.guest.knownHost.Ignore {
		// This is not insecure; see the controlling parameter description to find out why.
		return ssh.InsecureIgnoreHostKey(), nil
	}

	knownHostsList := d.guest.knownHost.List
	if len(knownHostsList) == 0 {
		knownHostsList = d.hypervisor.knownHost.List
	}

	knownHostsFile := d.guest.knownHost.File
	if knownHostsFile == "" {
		knownHostsFile = d.hypervisor.knownHost.File
	}

	pubKeys, err := getPubKeys(d.guest.hostname, d.GuestPort(), knownHostsList, knownHostsFile)
	if err != nil {
		return nil, err
	}

	return verifyKeys(ctx, d.guest.hostname, d.guest.sshfp, pubKeys), nil
}

func (d *EphemeralTunnelResourceData) HypervisorAcceptedAlgorithms(ctx context.Context) ([]string, error) {
	return getAcceptedAlgorithms(ctx, d.hypervisor.hostname, d.HypervisorPort(), d.hypervisor.knownHost.List, d.hypervisor.knownHost.File, d.hypervisor.sshfp)
}

func (d *EphemeralTunnelResourceData) GuestAcceptedAlgorithms(ctx context.Context) ([]string, error) {
	return getAcceptedAlgorithms(ctx, d.guest.hostname, d.GuestPort(), d.guest.knownHost.List, d.guest.knownHost.File, d.guest.sshfp)
}

// ValidateConfig is called during the Open call on the ephemeral resource to validate configuration validity and consistency with all available data, including provider configuration
func (d *EphemeralTunnelResourceData) ValidateConfig(ctx context.Context) diag.Diagnostics {
	if d.hypervisor.hostname == "" {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: hostname is not set; it must be configured at least once either in the provider configuration or the ephemeral resource configuration",
			),
		}
	}
	// Port is not checked because the port defaults to 22 if not defined
	// Username is not checked because the username defaults to "root" if not defined
	if d.hypervisor.password == "" && !d.hypervisor.agent.Use && d.hypervisor.privateKey.Path == "" {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: at least one authentication method for the hypervisor must be defined; none were provided either in the provider configuration or the ephemeral resource configuration",
			),
		}
	}
	if len(d.hypervisor.knownHost.List) == 0 && d.hypervisor.knownHost.File == "" && !d.hypervisor.sshfp.Use {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: at least one known host entry for the hypervisor must be defined; none were provided either in the provider configuration or the ephemeral resource configuration",
			),
		}
	}

	// If authn to hypervisor is done by password and since we refuse to use the hypervisor password to authenticate with the guest, either a password must be defined for the guest or another authentication mechanism must be specified
	if d.guest.password == "" && !d.hypervisor.agent.Use && !d.guest.agent.Use && d.hypervisor.privateKey.Path == "" && d.guest.privateKey.Path == "" {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: guest authentication cannot use the hypervisor password; at least one authentification method must be defined for the guest",
			),
		}
	}

	// The hostname being a domain name is tested by checking that the hostname cannot be parsed as an IP address, because domain names have such large acceptance criteria that, strictly speaking, an IP address is a valid domain name...
	parsedHostname := net.ParseIP(d.hypervisor.hostname)
	if d.hypervisor.sshfp.Use && parsedHostname != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"invalid configuration",
				"invalid configuration: host verification is done by querying the DNS for SSHFP records, but the hostname is an IP address and not a domain name",
			),
		}
	}

	if diags := sshfp.ValidateConfig(ctx, basetypes.NewStringValue(d.hypervisor.hostname), basetypes.NewBoolValue(d.hypervisor.sshfp.Use), basetypes.NewStringValue(d.hypervisor.sshfp.DNSRecursiveServerAddress), "hypervisor"); diags.HasError() {
		return diags
	}
	if diags := sshfp.ValidateConfig(ctx, basetypes.NewStringValue(d.guest.hostname), basetypes.NewBoolValue(d.guest.sshfp.Use), basetypes.NewStringValue(d.guest.sshfp.DNSRecursiveServerAddress), "guest"); diags.HasError() {
		return diags
	}

	var knownHosts []attr.Value
	for _, entry := range d.guest.knownHost.List {
		knownHosts = append(knownHosts, basetypes.NewStringValue(entry))
	}
	knownHostList, diags := basetypes.NewListValue(types.StringType, knownHosts)
	if diags.HasError() {
		return diags
	}
	if diags := hostkeychecking.ValidateConfig(basetypes.NewStringValue(d.guest.hostname), basetypes.NewBoolValue(d.guest.knownHost.Ignore), knownHostList, basetypes.NewStringValue(d.guest.knownHost.File), basetypes.NewBoolValue(d.guest.sshfp.Use)); diags.HasError() {
		return diags
	}
	return nil
}
