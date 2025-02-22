// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/authn"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/fileexists"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshfp"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshprivkey"
	ssh2vsock_types "github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/provider"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/dns"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ip"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ipport"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/known_hosts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
)

var (
	_ datasource.DataSource                     = (*KnownHostDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*KnownHostDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*KnownHostDataSource)(nil)
)

type KnownHostDataSource struct {
	providerData *terraform.ProviderDataModel
}

func NewKnownHostDataSource() datasource.DataSource {
	return &KnownHostDataSource{}
}

func (ds *KnownHostDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s", req.ProviderTypeName, "known_host")
}

func (ds *KnownHostDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `The "ssh2vsock_known_host" data source provides a way to fetch the various SSH host public keys of a guest virtual machine.

It basically acts as a "ssh-keyscan" alternative to scan hosts accessible using AF_VSOCK sockets.

Generally, the same set of host keys is used on the AF_VSOCK socket and on the TCP socket.
This means the practitioner can securely fetch the host public keys over AF_VSOCK with this data source, then generate the known host entries using the "make_known_host" provided function and finally establish a verified SSH connection over TCP using these known host entries.

This workflow relies on the reasonable assumption that the hypervisor is already implicitly trusted and that it will "route" the SSH key scanning performed by this data source reliably by contacting the appropriate guest VM identified by its Context ID (CID).
`,
		Attributes: map[string]schema.Attribute{
			"hypervisor": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: `The "hypervisor" attribute specifies how to connect to the hypervisor running the guest VM that the practitioner wants to interact with.

This attribute specifies values for this specific data source instance. If this attribute is not specified or null, values from the provider "hypervisor" attribute will be used instead.

This attribute MUST be specified at least once at the provider level or at the data source level. A combination of values from the provider level and the data source level can be used simultaneously, as long as all the required fields are specified at least once. Overriding values from the provider level is permitted.

This inheritance allows for a form of factorization/centralization of common values, while allowing some flexibility at the data source level.
`,
				Attributes: map[string]schema.Attribute{
					"hostname": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "hostname" attribute serves the same purpose as the provider level "hostname" attribute.

It specifies the name or the IPv4 or IPv6 address of the hypervisor running the guest VM whose SSH public keys must be retrieved.

If the SSHFP verification method is used, the hostname value MUST be a domain name.

This attribute must be defined either at the provider level or the data source level. If it is not defined at the data source level, the provider level value is used. If it is specified at both levels, the data source value is used. If neither are specified, an error is raised at the plan and apply phases.
`,
						Validators: []validator.String{
							stringvalidator.Any(
								&dns.DNSValidator{},
								&ip.IPValidator{},
							),
						},
					},
					"port": schema.Int32Attribute{
						Optional: true,
						MarkdownDescription: `The "port" attribute serves the same purpose as the provider level "port" attribute.

It specifies the port on which the SSH service of the hypervisor is listening.

This attribute can be defined at the provider level or the data source level. If it is not defined at the data source level, the provider level value is used. If it is specified at both levels, the data source value is used. It neither are specified, port 22 is used.
`,
						Validators: []validator.Int32{
							int32validator.Between(0, 65535),
						},
					},
					"username": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "username" attribute serves the same purpose as the provider level "username" attribute.

It specifies the name of the user account to authenticate to, once the SSH connection is established.

This attribute can be specified at the provider level or the data source level. If it is not defined at the data source level, the provider level value is used. It is specified at both levels, the data source value is used. It neither are specified, the "root" username is used.
`,
					},
					"ssh_private_key": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_key" attribute serves the same purpose as the provider level "ssh_private_key" attribute.

It specifies the path of a file containing a SSH private key. The key cannot be encrypted because Terraform data sources do not support Write Only attributes at the time of writing. This means the passphrase would risk being stored in the state. If you need to use an encrypted private key, specify the authentication mechanism as the provider level.

At most one authentication method must be defined. The authentication mechanism attributes are "ssh_private_key" and "ssh_use_agent".

This attribute can be specified at the provider level or the data source level. If no authentication mechanism is specified at the data source level, the authentication mechanism specified at the provider level is used. If an authentication mechanism is defined at the data source level, this authentication mechanism is used and the provider level authentication mechanism is completely ignored.
`,
					},
					"ssh_use_agent": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_use_agent" attribute serves the same purpose as the provider level "ssh_use_agent" attribute.

If true, SSH authentication is performed using the keys added to the specified SSH agent.

At most one authentication method must be defined. The authentication mechanism attributes are "ssh_private_key" and "ssh_use_agent".

This attribute can be specified at the provider level or at the data source level. If no authentication mechanism is specified at the data source level, the authentication mechanism at the provider level is used. If an authentication mechanism is defined at the data source level, this authentication mechanism is used and the provider level authentication mechanism is completely ignored.
`,
					},
					"ssh_agent_sock": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_agent_sock" attribute serves the same purpose as the provider level "ssh_agent_sock" attribute.

It specifies the path to the UNIX socket on which the SSH agent listens.

If this attribute is specified at the data source level, this value is used. If this attribute is not defined at the data source level, but it is specified at the provider level, the provider value is used.

If this attribute is not specified at all, the value of the SSH_AUTH_SOCK environment variable is used instead. If that variable is not set, an error will be raised during the plan and apply phases.

The value of this attribute is ignored if "ssh_use_agent" is not specified or false.
`,
					},
					"known_hosts": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						MarkdownDescription: `The "known_host" attribute serves the same purpose as the provider level "known_host" attribute.

It specifies a list of known host entries, one per list item, in the classic SSH known_host file entries. These entries are used to verify the host key of the SSH server.

Only entries matching the name or IP address specified by the "hostname" attribute are used. Entries can specify the hostname either as hashed or non-hashed values.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_host", "known_host_file" and "use_sshfp".

These attributes are additive: all entries from these host key verification mechanisms matching the hostname are used.

This data source will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the data source level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the data source level, the values specified at the provider level are used. If no host key verification mechanism is specified at the data source level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
						Validators: []validator.List{
							&known_hosts.KnownHostsValidator{},
						},
					},
					"known_hosts_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "known_host" attribute serves the same purpose as the provider level "known_hosts_file" attribute.

It specifies the path of a file containing known host entries, in the classic SSH known_hosts file format. A classic value would be $HOME/.ssh/known_hosts, although please bear in mind that Terraform does not expand environment variables.

Only entries matching the name or IP address specified by the "hostname" attribute are used. Entries can specify the hostname either as hashed or non-hashed values.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_host", "known_host_file" and "use_sshfp".

These attributes are additive: all entries from these host key verification mechanisms matching the hostname are used.

This data source will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the data source level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the data source level, the values specified at the provider level are used. If no host key verification mechanism is specified at the data source level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
					"use_sshfp": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "use_sshfp" attribute serves the same purpose as the provider level "use_sshfp" attribute.

If true, SSHFP records will be queried at the hostname specified by the "hostname" attribute. When this attribute is true, the "hostname" attribute must be a domain name. If it is an IP address, an error will be raised at the validate, plan and apply phases.

Only SHA256 fingerprints returned by the DNS are considered, since SHA1 is now obsolete.

Only records signed with DNSSEC and verified by the DNS resolver (i.e. the AD bit must be set in the answer) are considered.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_host", "known_host_file" and "use_sshfp".

These attributes are additive: all entries from these host key verification mechanisms matching the hostname are used.

This data source will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the data source level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the data source level, the values specified at the provider level are used. If no host key verification mechanism is specified at the data source level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
					"dns_resolver": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "dns_resolver" attribute serves the same purpose as the provider level "dns_resolver" attribute.

It specifies the IPv4 or IPv6 address and port of the DNS server to use to query for SSHFP records. IPv6 addresses must be specified between square brackets (e.g. "[2001:db8::1]:53"), and local-link addresses must specify the interface using the % syntax (e.g. "[fe80::0102:03ff:fe04:0506%eth0]:53").

Unless the "ca_file" is also specified, it is **STRONGLY** recommended that the address and port point to a local DNSSEC validator or that the DNS messages are transported over a secure channel (WireGuard, IPsec, etc.). TSIG is not supported.

The transport protocol is TCP.

If this attribute is specified at the data source level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the data source level, the values specified at the provider level are used. If no host key verification mechanism is specified at the data source level, nor at the provider level, an error will be raised during the plan and apply phases.

This attribute must be set if use_sshfp is true, otherwise an error will be raised during the validate, plan and apply phases.
`,
						Validators: []validator.String{
							&ipport.IPPortValidator{},
						},
					},
					"ca_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ca_file" attribute serves the same purpose as the provider level "ca_file" attribute.

It specifies the path to a file containing a collection of certification authority trusted certificates, concatenated in PEM format. A classic value could be "/etc/ssl/certs/ca-certificates.crt".

If this attribute is specified, the provider uses DNS over TLS to query the DNS server and expects the DNS server to offer a TLS certificate that can be verified by one of the trusted certificates.

If this attribute is specified at the data source level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the data source level, the values specified at the provider level are used. If no host key verification mechanism is specified at the data source level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
				},
			},
			"guest": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: `The "guest" attribute specifies the information required to connect to the guest virtual machine whose host keys must be retrieved.`,
				Attributes: map[string]schema.Attribute{
					"cid": schema.Int32Attribute{
						Required: true,
						MarkdownDescription: `The "cid" attribute specifies the Context ID (CID) of the guest virtual machine whose host keys must be retrieved.

The CID of the virtual machine is like its address for AF_VSOCK sockets.

Valid values start at 3; lower values are special case values not useful in the context of this provider.
`,
						Validators: []validator.Int32{
							int32validator.AtLeast(3),
						},
					},
					"port": schema.Int32Attribute{
						Optional: true,
						MarkdownDescription: `The "port" attribute specifies the AF_VSOCK port on which the guest virtual machine SSH service listens.

If this attribute is not specified at the data source guest level, the value specified by the "port" attribute at the data source hypervisor level is used. If none of these values are specified, the value specified by the "port" attribute at the provider level is used. If no values are specified at all, the provider defaults to the default port: 22.
`,
						Validators: []validator.Int32{
							int32validator.Between(0, 65535),
						},
					},
				},
			},
			"rsa_known_host": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: `The "rsa_known_host" attribute is set to the RSA public key offered by the guest virtual machine SSH service. If the SSH server does not offer a RSA host key, this attribute is set to null.`,
			},
			"ecdsa_known_host": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: `The "ecdsa_known_host" attribute is set to the ECDSA public key offered by the guest virtual machine SSH service. If the SSH server does not offer a ECDSA host key, this attribute is set to null.`,
			},
			"ed25519_known_host": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: `The "ed25519_known_host" attribute is set to the ED25519 public key offered by the guest virtual machine SSH service. If the SSH server does not offer a ED25519 host key, this attribute is set to null.`,
			},
		},
	}
}

func (ds *KnownHostDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	rawData := req.ProviderData
	if rawData == nil {
		return
	}

	provData, ok := rawData.(*terraform.ProviderDataModel)
	if !ok {
		resp.Diagnostics.AddError(
			"invalid provider data data type",
			"invalid provider data data type; cast failed",
		)
	}
	ds.providerData = provData
}

func (ds *KnownHostDataSource) returnUnknown(reqCtx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var dsTFData terraform.KnownHostModel
	if diags := req.Config.Get(reqCtx, &dsTFData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	dsTFData.RSAKnownHost = basetypes.NewStringUnknown()
	dsTFData.ECDSAKnownHost = basetypes.NewStringUnknown()
	dsTFData.ED25519KnownHost = basetypes.NewStringUnknown()
	if diags := resp.State.Set(reqCtx, dsTFData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (ds *KnownHostDataSource) Read(reqCtx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {

	dsData, unknown, diags := ssh2vsock_types.KnownHostDatasourceFromTFConfig(reqCtx, req.Config)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	// If some values are unknown, we cannot return known values yet, so we bail out
	if unknown {
		ds.returnUnknown(reqCtx, req, resp)
		return
	}

	if unknown, diags := dsData.MergeProviderData(reqCtx, ds.providerData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	} else if unknown {
		ds.returnUnknown(reqCtx, req, resp)
		return
	}

	if diags := dsData.ValidateConfig(); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	var guestDiags diag.Diagnostics
	for _, keyAlgoConstraint := range [][]string{{ssh.KeyAlgoRSA, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512}, {ssh.KeyAlgoECDSA256}, {ssh.KeyAlgoED25519}} {
		sshContext, cancelFunc := context.WithCancel(reqCtx)
		defer cancelFunc()

		hypervisorSSHClient, diags := openHypervisorConnection(reqCtx, sshContext, dsData)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}

		_, diags = openGuestConnection(reqCtx, sshContext, hypervisorSSHClient, dsData, dsData, keyAlgoConstraint)
		// We expect this call to fail, because we did not provide any authentication mechanism, but this is OK as long as we do get the guest public key; we just store them in case we need to return them if absolutely NO public key was retrived
		guestDiags.Append(diags...)
	}

	rsaPubKey := dsData.GuestPublicKey(ssh.KeyAlgoRSA)
	ecdsaPubKey := dsData.GuestPublicKey(ssh.KeyAlgoECDSA256)
	ed25519PubKey := dsData.GuestPublicKey(ssh.KeyAlgoED25519)

	if rsaPubKey == nil && ecdsaPubKey == nil && ed25519PubKey == nil && guestDiags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	var dsTFData terraform.KnownHostModel
	if diags := req.Config.Get(reqCtx, &dsTFData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if rsaPubKey != nil {
		dsTFData.RSAKnownHost = basetypes.NewStringValue(base64.StdEncoding.EncodeToString(rsaPubKey.Marshal()))
	} else {
		dsTFData.RSAKnownHost = basetypes.NewStringNull()
	}
	if ecdsaPubKey != nil {
		dsTFData.ECDSAKnownHost = basetypes.NewStringValue(base64.StdEncoding.EncodeToString(ecdsaPubKey.Marshal()))
	} else {
		dsTFData.ECDSAKnownHost = basetypes.NewStringNull()
	}
	if ed25519PubKey != nil {
		dsTFData.ED25519KnownHost = basetypes.NewStringValue(base64.StdEncoding.EncodeToString(ed25519PubKey.Marshal()))
	} else {
		dsTFData.ECDSAKnownHost = basetypes.NewStringNull()
	}

	if diags := resp.State.Set(reqCtx, dsTFData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (ds *KnownHostDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		&authn.Authn{},
		&sshfp.SSHFP{},
		&sshprivkey.PrivateKey{},
		&fileexists.File{},
	}
}
