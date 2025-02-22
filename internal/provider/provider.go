// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"context"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/authn"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/fileexists"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshfp"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshprivkey"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/dns"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ip"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ipport"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/known_hosts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ provider.ProviderWithEphemeralResources = (*SSH2VSockProvider)(nil)
	_ provider.ProviderWithFunctions          = (*SSH2VSockProvider)(nil)
	_ provider.ProviderWithConfigValidators   = (*SSH2VSockProvider)(nil)
)

type SSH2VSockProvider struct {
	version string
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &SSH2VSockProvider{
			version: version,
		}
	}
}

func (p *SSH2VSockProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ssh2vsock"
	resp.Version = p.version
}

func (p *SSH2VSockProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `The ssh2vsock provider enables practitioners to reach virtual machines over SSH via their hypervisor using [AF_VSOCK sockets](https://www.man7.org/linux/man-pages/man7/vsock.7.html).

As opposed to most SSH-related Terraform providers, this one goes a long way in order to secure the SSH connections by verifying the host keys using a list of known host entries, a classic known host file or [SSHFP](https://www.rfc-editor.org/rfc/rfc4255) records. It is compatible with both hashed and non-hashed known host entries.

This provider can also be used to secure SSH connections of other insecure SSH connections by tunneling their insecure communications over a secure series of tunnels.

It also provides utility functions to generate known host entries and structured SSHFP records to insert into the DNS.

SSHFP fingerprints must be signed with DNSSEC and verified (AD bit set) to be trusted, and the provider offers optional support of DNS-over-TLS with certificate verification to transport the result of the DNSSEC signature verification.

This provider only negotiates host key algorithms for which it has a known host entry or a SSHFP fingerprint. That is to say that if the only known host entry configured uses ssh-ed25519, then only ssh-ed25519 will be proposed during the handshake as an acceptable host key algorithm. If you get an error about a handshake failure because of the lack of common host key algorithms, please consider adding some known host entries with an algorithm that is currently accepted by the server.

This provider requires the guest VMs SSH service to listen on the AF_VSOCK address family. This is generally achieved thanks to [systemd socket activation](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html#ListenStream=) and [systemd ssh configuration generator](https://www.freedesktop.org/software/systemd/man/devel/systemd-ssh-generator.html) that automatically detects the virtual machine environment.

This provider also requires that the VM is configured with a AF_VSOCK context ID. With KVM, this is generally done by adding an argument, such as "-device vhost-vsock-pci,guest-cid=3". See [QEMU documentation](https://wiki.qemu.org/Features/VirtioVsock) for more information.

Finally, this provider requires that the [socat](http://www.dest-unreach.org/socat/) binary is installed on the hypervisor.
`,
		Attributes: map[string]schema.Attribute{
			"hypervisor": schema.SingleNestedAttribute{
				Optional:    true,
				Description: `The hypervisor attributes are inherited by all data sources and resources defined by this provider when a value is not specified in those data sources or resources themselves.`,
				Attributes: map[string]schema.Attribute{
					"hostname": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "hostname" attribute is used to specify the address of the hypervisor. This field value can either be a valid domain name or an IP4 or IPv6 address.

If the value is a domain name, this domain name can be queried for [SSHFP](https://www.rfc-editor.org/rfc/rfc4255) records in order to validate the SSH host key presented by the hypervisor.
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
						MarkdownDescription: `The "port" attribute specifies the TCP port on which the hypervisor SSH service is listening.

If this attribute is not defined by the practitioner at the provider level nor at the data source/resource level, port 22 is used by default.

If this attribute is defined and the guest port at the data source/resource level is not, this value is used instead of falling back on the port by default.`,
						Validators: []validator.Int32{
							int32validator.Between(0, 65535),
						},
					},
					"username": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "username" attribute specifies the username of the account to use on the hypervisor to establish an authenticated session.

If this attribute is not defined by the practitioner at the provider level nor at the data source/resource level, the "root" user is used by default.

If this attribute is defined and the guest username at the data source/resource level is not, this value is used instead of falling back on the username by default.`,
					},
					"password": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `Although not recommended, the "password" attribute enables password authentication for the hypervisor.

As opposed to the port and username attributes, this attribute is never used for guest authentication, as it would make no sense to have the same password on the hypervisor and on the guest.

At most one authentication method must be defined, among "password", "ssh_private_key" and "ssh_use_agent".`,
						Sensitive: true,
					},
					"ssh_private_key": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_key" attribute specifies the path to a file containing the SSH private key to use to authenticate to the hypervisor.

If this attribute is defined and the hypervisor and guest "ssh_private_key" attributes at the data source/resource level are not, this value will also be used for guest authentication.

The specified private key can be protected by a password or not. If so, the "ssh_private_key_passphrase" attribute must also be defined.

At most one authentication method must be defined, among "password", "ssh_private_key" and "ssh_use_agent".`,
					},
					"ssh_private_key_passphrase": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_key_passphrase" attribute specifies the password that must be used to decrypt the encrypted private key specified by the "ssh_private_key" attribute.

This attribute value is only used at the data source/resource level if the "ssh_private_key" is not specified at the data source/resource level. Specifying this attribute at the provider level and not specifying the "ssh_private_key" attribute at the provider level would make no sense, because a passphrase should never be shared between multiple encrypted private keys.`,
						Sensitive: true,
					},
					"ssh_use_agent": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_use_agent" attribute specifies whether a SSH agent should be used for authentication.

If this attribute is defined and no hypervisor authentication mechanism is defined at the data source/resource level, this value will be used.

If this attribute is defined and no hypervisor and guest authentication mechanisms are defined at the data source/resource level, this value will also be used for guest authentication.

At most one authentication method must be defined, among "password", "ssh_private_key" and "ssh_use_agent".`,
					},
					"ssh_agent_sock": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_agent_sock" attribute specifies the path of the UNIX socket file to connect to the SSH agent used for authentication.

If this attribute can be defined even if "ssh_use_agent" is not specified or false. It so, it will be inherited by data sources and resources if they set "ssh_use_agent" to true for the hypervisor or the guest.

If this attribute is not set at the provider level nor at the data source/resource level, the value of the SSH_AUTH_SOCK environment variable is used. If this variable is not set and "ssh_use_agent" is true for a data source/resource hypervisor or guest, an error is raised during the plan or apply phases.`,
					},
					"known_hosts": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						MarkdownDescription: `The "known_hosts" attribute specifies a list of known host entries, one per list entry. The syntax is the same as the one found in standard SSH known_hosts files.

Hashed and non-hashed hostnames are supported.

Entries regarding a different hostname than the one specified in the "hostname" attribute at the provider or the data source/resource level are silently ignored. This allows the practitioner to insert all known hosts entries at the provider level and specify the hostname of the hypervisor and the guests at the data source/resource level.

If this attribute is defined and no host key verification attributes are defined at the data source/resource level, then the value of this attribute is used for the hypervisor and/or guest host key verification.

This attribute is additive: if the "known_host_file" attribute is set at the provider level, entries from this attribute are considered as well as the entries from the "known_host_file" attribute. The same logic applies to "use_sshfp" defined at the provider level and the fingerprints received from the DNS.`,
						Validators: []validator.List{
							&known_hosts.KnownHostsValidator{},
						},
					},
					"known_hosts_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "known_hosts_file" attribute specifies the path to a file containing known host entries. This file is generally your "$HOME/.ssh/known_hosts" file. Please bear in mind $HOME won't be expanded in Terraform and you have to expand it yourself or some other way.

Hashed and non-hashed hostnames are supported.

Entries regarding a different hostname than the one specified in the "hostname" attribute at the provider or the data source/resource level are silently ignored. This allows the practitioner to specify a known_hosts file at the provider level and specify the hostname of the hypervisor and the guests at the data source/resource level.

If this attribute is defined and no host key verification attributes are defined at the data source/resource level, then the value of this attribute is used for the hypervisor and/or guest host key verification.

This attribute is additive: if the "known_hosts" attribute is set at the provider level, entries from this attribute are considered as well as the entries from the "known_hosts" attribute. The same logic applies to "use_sshfp" defined at the provider level and the fingerprints received from the DNS.`,
					},
					"use_sshfp": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "use_sshfp" attribute controls whether the provider should query the DNS for SSHFP records hosted at the name indicated by the "hostname" attribute.

SSHFP records must be DNSSEC signed and verified for them to be considered. Only fingerprints generated using SHA256 are considered valid, as SHA-1 is now insecure.

If this attribute is defined and no host key verification attributes are defined at the data source/resource level, then the value of this attribute is used for the hypervisor and/or guest host key verification.

This attribute is additive: if the "known_hosts" attribute is set at the provider level, fingerprints retrieved from the DNS are considered as well as the entries from the "known_hosts" attribute. The same logic applies to "known_host_file" defined at the provider level.
`,
					},
					"dns_resolver": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "dns_resolver" attribute specifies the IPv4 or IPv6 address and port to connect to in order to fetch SSHFP records. IPv6 addresses must be surrounded by square brackets (e.g. "[2001:db8::1]:53"). Local-link IPv6 addresses must specify the interface name as well (e.g. [fe80::0102:03ff:fe04:0506%eth0]:53).

Unless the "ca_file" is also specified, it is **STRONGLY** recommended that the address and port point to a local DNSSEC validator or that the DNS messages are transported over a secure channel (WireGuard, IPsec, etc.). TSIG is not supported.

The transport protocol is TCP.

If this attribute is defined and no host key verification attribute is defined at the data source/resource level, then the value of this attribute is used for the hypervisor and/or the guest host key verification.
`,
						Validators: []validator.String{
							&ipport.IPPortValidator{},
						},
					},
					"ca_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ca_file" attribute specifies that DNS-over-TLS (DoT) must be used to query SSHFP records and that the TLS server must offer a valid TLS server certificate chain. The validity of the TLS certificate chain is verified using one of the root certificates listed in the file designated by the value of this attribute. A common value for this attribute would be "/etc/ssl/certs/ca-certificates.crt".

The file format is a concatenated series of root certificates in PEM format.

If this attribute is defined and no host key verification attribute is defined at the data source/resource level, then the value of this attribute is used for the hypervisor and/or the guest host key verification.
`,
					},
				},
			},
		},
	}
}

func (p *SSH2VSockProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var providerData terraform.ProviderDataModel
	if diags := req.Config.Get(ctx, &providerData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.DataSourceData = &providerData
	resp.EphemeralResourceData = &providerData
}

func (p *SSH2VSockProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewKnownHostDataSource,
	}
}

func (p *SSH2VSockProvider) Resources(ctx context.Context) []func() resource.Resource {
	return nil
}

func (p *SSH2VSockProvider) EphemeralResources(ctx context.Context) []func() ephemeral.EphemeralResource {
	return []func() ephemeral.EphemeralResource{
		NewSSH2VSockEphemeralResource(),
	}
}

func (p *SSH2VSockProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{
		NewKnownHostFunc,
		NewSSHFPFunc,
	}
}

func (p *SSH2VSockProvider) ConfigValidators(_ context.Context) []provider.ConfigValidator {
	return []provider.ConfigValidator{
		&authn.Authn{},
		&sshfp.SSHFP{},
		&sshprivkey.PrivateKey{},
		&fileexists.File{},
	}
}
