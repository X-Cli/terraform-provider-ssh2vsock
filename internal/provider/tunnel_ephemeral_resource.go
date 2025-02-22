// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/authn"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/fileexists"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/hostkeychecking"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshfp"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/config_validators/sshprivkey"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/dns"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ip"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ipport"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/crypto/ssh"

	ssh2vsock_types "github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/provider"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/known_hosts"
)

const (
	sshConnReadBufferSize = 1024 * 1024
	readMaxDuration       = time.Second
	writeMaxDuration      = time.Second
)

var (
	_ ephemeral.EphemeralResourceWithClose            = (*TunnelResource)(nil)
	_ ephemeral.EphemeralResourceWithConfigure        = (*TunnelResource)(nil)
	_ ephemeral.EphemeralResourceWithConfigValidators = (*TunnelResource)(nil)
)

type TunnelResource struct {
	providerData *terraform.ProviderDataModel
	cancelFunc   context.CancelFunc
}

func NewSSH2VSockEphemeralResource() func() ephemeral.EphemeralResource {
	return func() ephemeral.EphemeralResource {
		return &TunnelResource{}
	}
}

func (r *TunnelResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = fmt.Sprintf("%s_%s", req.ProviderTypeName, "tunnel")
}

func (r *TunnelResource) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: `The "ssh2vsock_tunnel" ephemeral resource provides a secure tunnel from the Terraform client to the guest virtual machine, using the hypervisor as a jump host and an AF_VSOCK relay.

The tunnel entrance is a local port opened by this resource. The tunnel exit connects to the SSH service of the guest virtual machine on its loopback interface.

Incidentally, the guest virtual machine SSH service is expected to listen on its loopback interface.

The added value of this ephemeral resource is that the SSH protocol only specifies TCP forwarding to hosts identified by their hostname or IP address. It does not specify ways to forward traffic on AF_INET(6) sockets. Connection forwarding to AF_UNIX and AF_VSOCK sockets requires special forwarding/proxying techniques that this provider implements, thanks to [socat](http://www.dest-unreach.org/socat/).

By relying on the AF_VSOCK address family, a secure tunnel can be established with the guest virtual machine, even if the guest has no NIC. It also enables secure connection establishment by leveraging the implicit trust of the hypervisor to route the AF_VSOCK connection to the right guest.

This resource also enables the establishment of a secure tunnel for other Terraform SSH clients that cannot verify SSH host keys.
`,
		Attributes: map[string]schema.Attribute{
			"hypervisor": schema.SingleNestedAttribute{
				Optional: true,
				MarkdownDescription: `The "hypervisor" attribute specifies how to connect to the hypervisor running the guest VM that the practitioner wants to interact with.

This attribute specifies values for this specific ephemeral resource instance. If this attribute is not specified or null, values from the provider "hypervisor" attribute will be used instead.

This attribute MUST be specified at least once at the provider level or at the ephemeral resource level. A combination of values from the provider level and the ephemeral resource level can be used simultaneously, as long as all the required fields are specified at least once. These ephemeral resource level values override the provider level values.

This inheritance allows for a form of factorization/centralization of common values, while allowing some flexibility at the ephemeral resource level.
`,
				Attributes: map[string]schema.Attribute{
					"hostname": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "hostname" attribute serves the same purpose as the provider level "hostname" attribute.

It specifies the name or the IPv4 or IPv6 address of the hypervisor running the guest VM to which a tunnel will be established.

If the SSHFP verification method is used, the hostname value MUST be a domain name.

This attribute must be defined either at the provider level or the ephemeral resource level. If it is not defined at the ephemeral resource level, the provider level value is used. If it is specified at both levels, the ephemeral resource value is used. If neither are specified, an error is raised at the plan and apply phases.
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

This attribute can be defined at the provider level or the ephemeral resource level. If it is not defined at the ephemeral resource level, the provider level value is used. If it is specified at both levels, the ephemeral resource value is used. It neither are specified, port 22 is used.
`,
						Validators: []validator.Int32{
							int32validator.Between(0, 65535),
						},
					},
					"username": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "username" attribute serves the same purpose as the provider level "username" attribute.

It specifies the name of the user account to authenticate to, once the SSH connection is established.

This attribute can be specified at the provider level or the ephemeral resource level. If it is not defined at the ephemeral resource level, the provider level value is used. It is specified at both levels, the ephemeral resource value is used. It neither are specified, the "root" username is used.
`,
					},
					"password": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "password" attribute serves the same purpose as the provider level "password" attribute.

It specifies a password to use during the authentication phase of the SSH protocol.

At most one authentication method must be defined. The authentication mechanism attributes are "password", "ssh_private_key" and "ssh_use_agent".

This attribute can be specified at the provider level or the ephemeral resource level. If no authentication mechanism is specified at the ephemeral resource level, the provider authentication mechanism specified at the provider level is used. If an authentication mechanism is defined at the ephemeral resource level, this authentication mechanism is used and the provider level authentication mechanism is completely ignored.
`,
						Sensitive: true,
					},
					"ssh_private_key": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_key" attribute serves the same purpose as the provider level "ssh_private_key" attribute.

It specifies the path of a file containing a SSH private key. The key can be encrypted or not. If it is, the "ssh_private_key_passphrase" must be specified too and it must contain the password to decrypt the private key.

At most one authentication method must be defined. The authentication mechanism attributes are "password", "ssh_private_key" and "ssh_use_agent".

This attribute can be specified at the provider level or the ephemeral resource level. If no authentication mechanism is specified at the ephemeral resource level, the authentication mechanism specified at the provider level is used. If an authentication mechanism is defined at the ephemeral resource level, this authentication mechanism is used and the provider level authentication mechanism is completely ignored.
`,
					},
					"ssh_private_key_passphrase": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_key_passphrase" attribute serves the same purpose as the provider level "ssh_private_key_passphrase" attribute.

It specifies the password to use to decrypt the private key specified by the "ssh_private_key" attribute.

This attribute is unused if the "ssh_private_key" attribute of this ephemeral resource is not specified. If this attribute is not specified, and "ssh_private_key" is, the private key is assumed to be unencrypted.

This attribute value is only inherited from the provider-level configuration if no authentication mechanism is specified at the ephemeral resource level. It would make no sense to assume that multiple SSH private keys are encrypted with the same password.
`,
						Sensitive: true,
					},
					"ssh_use_agent": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_use_agent" attribute serves the same purpose as the provider level "ssh_use_agent" attribute.

If true, SSH authentication is performed using the keys added to the specified SSH agent.

At most one authentication method must be defined. The authentication mechanism attributes are "password", "ssh_private_key" and "ssh_use_agent".

This attribute can be specified at the provider level or at the ephemeral resource level. If no authentication mechanism is specified at the ephemeral resource level, the authentication mechanism at the provider level is used. If an authentication mechanism is defined at the ephemeral resource level, this authentication mechanism is used and the provider level authentication mechanism is completely ignored.
`,
					},
					"ssh_agent_sock": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_agent_sock" attribute serves the same purpose as the provider level "ssh_agent_sock" attribute.

It specifies the path to the UNIX socket on which the SSH agent listens.

If this attribute is specified at the ephemeral resource level, this value is used. If this attribute is not defined at the ephemeral resource level, but it is specified at the provider level, the provider value is used.

If this attribute is not specified at all, the value of the SSH_AUTH_SOCK environment variable is used instead. If that variable is not set, an error will be raised during the plan and apply phases.

The value of this attribute is ignored if "ssh_use_agent" is not specified or false.
`,
					},
					"known_hosts": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						MarkdownDescription: `The "known_hosts" attribute serves the same purpose as the provider level "known_hosts" attribute.

It specifies a list of known host entries, one per list item, in the classic SSH known_host file entries. These entries are used to verify the host key of the SSH server.

Only entries matching the name or IP address specified by the "hostname" attribute are used. Entries can specify the hostname either as hashed or non-hashed values.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_hosts", "known_hosts_file" and "use_sshfp".

These attributes are additive: all entries from these host key verification mechanisms matching the hostname are used.

This ephemeral resource will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the ephemeral resource level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource level, the values specified at the provider level are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
						Validators: []validator.List{
							&known_hosts.KnownHostsValidator{},
						},
					},
					"known_hosts_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "known_hosts_file" attribute serves the same purpose as the provider level "known_hosts_file" attribute.

It specifies the path of a file containing known host entries, in the classic SSH known_hosts file format. A classic value would be $HOME/.ssh/known_hosts, although please bear in mind that Terraform does not expand environment variables.

Only entries matching the name or IP address specified by the "hostname" attribute are used. Entries can specify the hostname either as hashed or non-hashed values.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_hosts", "known_hosts_file" and "use_sshfp".

These attributes are additive: all entries from these host key verification mechanisms matching the hostname are used.

This ephemeral resource will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the ephemeral resource level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource level, the values specified at the provider level are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
					"use_sshfp": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "use_sshfp" attribute serves the same purpose as the provider level "use_sshfp" attribute.

If true, SSHFP records will be queried at the hostname specified by the "hostname" attribute. When this attribute is true, the "hostname" attribute must be a domain name. If it is an IP address, an error will be raised at the validate, plan and apply phases.

Only SHA256 fingerprints returned by the DNS are considered, since SHA1 is now obsolete.

Only records signed with DNSSEC and verified by the DNS resolver (i.e. the AD bit must be set in the answer) are considered.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_hosts", "known_hosts_file" and "use_sshfp".

These attributes are additive: all entries from these host key verification mechanisms matching the hostname are used.

This ephemeral resource will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the ephemeral resource level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource level, the values specified at the provider level are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
					"dns_resolver": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "dns_resolver" attribute serves the same purpose as the provider level "dns_resolver" attribute.

It specifies the IPv4 or IPv6 address and port of the DNS server to use to query for SSHFP records. IPv6 addresses must be specified between square brackets (e.g. "[2001:db8::1]:53"), and local-link addresses must specify the interface using the % syntax (e.g. "[fe80::0102:03ff:fe04:0506%eth0]:53").

Unless the "ca_file" is also specified, it is **STRONGLY** recommended that the address and port point to a local DNSSEC validator or that the DNS messages are transported over a secure channel (WireGuard, IPsec, etc.). TSIG is not supported.

The transport protocol is TCP.

If this attribute is specified at the ephemeral resource level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource level, the values specified at the provider level are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.

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

If this attribute is specified at the ephemeral resource level, all values specified at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource level, the values specified at the provider level are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
				},
			},
			"guest": schema.SingleNestedAttribute{
				Required:            true,
				MarkdownDescription: `The guest attribute specifies the information required to establish a connection and a tunnel to the guest virtual machine.`,
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
					"hostname": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "hostname" attribute is used to specify the hostname of the guest virtual machine.

This value is not used to establish the connection, since the CID is the address of the guest virtual machine.

This value is used for host key checking. Incidentally, the "hostname" must be specified except when "ssh_ignore_host_key" is true.
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
						MarkdownDescription: `The "port" attribute specifies the AF_VSOCK port on which the guest virtual machine SSH service listens.

If this attribute is not specified at the ephemeral resource guest attribute level, the value specified by the "port" attribute at the ephemeral resource "hypervisor" attribute level is used. If none of these values are specified, the value specified by the "port" attribute at the provider level is used. If no values are specified at all, the provider uses the default port: 22.
`,
						Validators: []validator.Int32{
							int32validator.Between(0, 65535),
						},
					},
					"username": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "username" attribute specifies the name of the account on the guest virtual machine to connect to.

If this attribute is not specified at the ephemeral resource guest attribute level, the value specified by the "username" attribute at the ephemeral resource "hypervisor" attribute level is used. If none of these values are specified, the value specified by the "username" attribute at the provider level is used. It no values are specified at all, the provider uses the default username: "root".
						`,
					},
					"password": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "password" attribute specifies the password to use to authenticate to the account on the guest virtual machine.

At most one authentication mechanism must be specified. Authentication mechanism attributes are "password", "ssh_private_key" and "ssh_use_agent".

If no authentication attribute is specified at the ephemeral resource "guest" attribute level, the authentication mechanism specified at the ephemeral resource "hypervisor" attribute is used. If no authentication mechanism is defined at the ephemeral resource level, the authentication mechanism specified at the provider level is used. If no authentication mechanism are defined at all, an error will be raised during the plan and apply phases.
`,
						Sensitive: true,
					},
					"ssh_private_key": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_key" attribute specifies the path to a file containing the SSH private key to use to authenticate to the account on the guest virtual machine.

The private key can be unencrypted or encrypted with the passphrase specified by the "ssh_private_key_passphrase" attribute.

At most one authentication mechanism must be specified. Authentication mechanism attributes are "password", "ssh_private_key" and "ssh_use_agent".

If no authentication attribute is specified at the ephemeral resource "guest" attribute level, the authentication mechanism specified at the ephemeral resource "hypervisor" attribute is used. If no authentication mechanism is defined at the ephemeral resource level, the authentication mechanism specified at the provider level is used. If no authentication mechanism is defined at all, an error will be raised during the plan and apply phases.
						`,
					},
					"ssh_private_key_passphrase": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_private_passphrase" attribute specifies an optional passphrase used to decrypt the private key specified by the "ssh_private_key" attribute.

If this attribute is not specified, the private key is assumed to be unencrypted.

This attribute value is only inherited from the provider level configuration if no authentication mechanism is specified at the ephemeral resource level. It would make no sense to assume that multiple SSH private keys are encrypted with the same password.
						`,
						Sensitive: true,
					},
					"ssh_use_agent": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_use_agent" attribute specifies if the SSH authentication is performed using the keys added to the specified SSH agent.

At most one authentication method must be defined. The authentication mechanism attributes are "password", "ssh_private_key" and "ssh_use_agent".

If no authentication attribute is specified at the ephemeral resource "guest" attribute level, the authentication mechanism specified at the ephemeral resource "hypervisor" attribute is used. If no authentication mechanism is defined at the ephemeral resource level, the authentication mechanism specified at the provider level is used. If no authentication mechanism are defined at all, an error will be raised during the plan and apply phases.
`,
					},
					"ssh_agent_sock": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_agent_sock" attribute serves the same purpose as the "ssh_agent_sock" attribute of the "hypervisor" attribute.

It specifies the path to the UNIX socket on which the SSH agent listens.

If this attribute is specified at the ephemeral resource "guest" attribute level, this value is used. If it is not specified by the ephemeral resource "guest" attribute, and but it is specified at the ephemeral resource "hypervisor" attribute, the hypervisor value is used. If it is not specified at the "hypervisor" attribute leve, but it is specified at the provider level, the provider value is used.

If this attribute is not specified at all, the value of the SSH_AUTH_SOCK environment variable is used instead. If that variable is not set, an error will be raised during the plan and apply phases.

The value of this attribute is ignored if "ssh_use_agent" is not specified or false.`,
					},
					"known_hosts": schema.ListAttribute{
						ElementType: types.StringType,
						Optional:    true,
						MarkdownDescription: `The "known_hosts" attribute specifies a list of known host entries, one per list item, in the classic SSH known_host file entries. These entries are used to verify the host key of the SSH server.

Only entries matching the name or IP address specified by the "hostname" attribute are used. Entries can specify the hostname either as hashed or non-hashed values.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_hosts", "known_hosts_file" "ssh_ignore_host_key" and "use_sshfp".

These attributes are additive (with the exception of "ssh_ignore_host_key"): all entries from these host key verification mechanisms matching the hostname are used.

This ephemeral resource will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the ephemeral resource "guest" attribute level, all values specified at the ephemeral resource "hypervisor" attribute and at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource "guest" attribute level, the values specified at the ephemeral resource "hypervisor" attribute are used. If no host key verification mechanism is specified at the ephemeral resource "hypervisor" attribute level, the provider level values are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
						Validators: []validator.List{
							&known_hosts.KnownHostsValidator{},
						},
					},
					"known_hosts_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "known_host_file" attribute specifies the path of a file containing known host entries, in the classic SSH known_hosts file format. A classic value would be $HOME/.ssh/known_hosts, although please bear in mind that Terraform does not expand environment variables.

Only entries matching the name or IP address specified by the "hostname" attribute are used. Entries can specify the hostname either as hashed or non-hashed values.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_hosts", "known_hosts_file", "ssh_ignore_host_key" and "use_sshfp".

These attributes are additive (with the exception of "ssh_ignore_host_key"): all entries from these host key verification mechanisms matching the hostname are used.

This ephemeral resource will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the ephemeral resource "guest" attribute level, all values specified at the ephemeral resource "hypervisor" attribute and at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource "guest" attribute level, the values specified at the ephemeral resource "hypervisor" attribute are used. If no host key verification mechanism is specified at the ephemeral resource "hypervisor" attribute level, the provider level values are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
					"ssh_ignore_host_key": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "ssh_ignore_host_key" attribute controls whether the host key used by the SSH service of the guest virtual machine is verified or not.

If this attribute is set to true, no host key verification happens. Setting this attribute to true and setting another host key verification mechanism for the guest makes no sense and will raise a validate, plan and apply error.

Ignoring the host key is not necessarily a security risk here because the hypervisor is implicitly trusted to route the traffic to the appropriate guest virtual machine.
`,
					},
					"use_sshfp": schema.BoolAttribute{
						Optional: true,
						MarkdownDescription: `The "use_sshfp" attribute serves the same purpose as the hypervisor attribute level "use_sshfp" attribute.

If true, SSHFP records will be queried at the hostname specified by the "hostname" attribute. When this attribute is true, the "hostname" attribute must be a domain name. If it is an IP address, an error will be raised at the validate, plan and apply phases.

Only SHA256 fingerprints returned by the DNS are considered, since SHA1 is now obsolete.

Only records signed with DNSSEC and verified by the DNS resolver (i.e. the AD bit must be set in the answer) are considered.

At least one host key verification mechanism must be specified. Host key verification attributes are "known_hosts", "known_hosts_file" "ssh_ignore_host_key" and "use_sshfp".

These attributes are additive (with the exception of "ssh_ignore_host_key"): all entries from these host key verification mechanisms matching the hostname are used.

This ephemeral resource will only attempt to negotiate host key algorithms for which a known host key is specified in one of the host key verification mechanisms.

If this attribute is specified at the ephemeral resource "guest" attribute level, all values specified at the ephemeral resource "hypervisor" attribute and at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource "guest" attribute level, the values specified at the ephemeral resource "hypervisor" attribute are used. If no host key verification mechanism is specified at the ephemeral resource "hypervisor" attribute level, the provider level values are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
					"dns_resolver": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "dns_resolver" attribute serves the same purpose as the "hypervisor" attribute level "dns_resolver" attribute.

It specifies the IPv4 or IPv6 address and port of the DNS server to use to query for SSHFP records. IPv6 addresses must be specified between square brackets (e.g. "[2001:db8::1]:53"), and local-link addresses must specify the interface using the % syntax (e.g. "[fe80::0102:03ff:fe04:0506%eth0]:53").

Unless the "ca_file" is also specified, it is **STRONGLY** recommended that the address and port point to a local DNSSEC validator or that the DNS messages are transported over a secure channel (WireGuard, IPsec, etc.). TSIG is not supported.

The transport protocol is TCP.

If this attribute is specified at the ephemeral resource "guest" attribute level, all values specified at the ephemeral resource "hypervisor" attribute and at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource "guest" attribute level, the values specified at the ephemeral resource "hypervisor" attribute are used. If no host key verification mechanism is specified at the ephemeral resource "hypervisor" attribute level, the provider level values are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.

This attribute must be set if use_sshfp is true, otherwise an error will be raised during the validate, plan and apply phases.
`,
						Validators: []validator.String{
							&ipport.IPPortValidator{},
						},
					},
					"ca_file": schema.StringAttribute{
						Optional: true,
						MarkdownDescription: `The "ca_file" attribute serves the same purpose as the "hypervisor" attribute level "ca_file" attribute.

It specifies the path to a file containing a collection of certification authority trusted certificates, concatenated in PEM format. A classic value could be "/etc/ssl/certs/ca-certificates.crt".

If this attribute is specified, the provider uses DNS over TLS to query the DNS server and expects the DNS server to offer a TLS certificate that can be verified by one of the trusted certificates.

If this attribute is specified at the ephemeral resource "guest" attribute level, all values specified at the ephemeral resource "hypervisor" attribute and at the provider level are ignored. If no host key verification mechanism is specified at the ephemeral resource "guest" attribute level, the values specified at the ephemeral resource "hypervisor" attribute are used. If no host key verification mechanism is specified at the ephemeral resource "hypervisor" attribute level, the provider level values are used. If no host key verification mechanism is specified at the ephemeral resource level, nor at the provider level, an error will be raised during the plan and apply phases.
`,
					},
				},
			},
			"listen_port": schema.Int32Attribute{
				Computed:            true,
				MarkdownDescription: `The "listen_port" attribute specifies the TCP port that accepts connections to be tunneled to the guest virtual machine.`,
				Validators: []validator.Int32{
					int32validator.Between(1, 65535),
				},
			},
		},
	}
}

func (r *TunnelResource) Configure(ctx context.Context, req ephemeral.ConfigureRequest, resp *ephemeral.ConfigureResponse) {
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
	r.providerData = provData
}

func handleTrafficCopy(reqCtx, sshContext context.Context, fromConn, toConn net.Conn) {
	var b [sshConnReadBufferSize]byte
	for {
		rn, err := fromConn.Read(b[:])
		switch err {
		case io.EOF:
			return
		case nil:
		default:
			tflog.Error(reqCtx, fmt.Sprintf("failed to read from input connection: %s", err.Error()))
		}

		select {
		case <-sshContext.Done():
			return
		default:
		}

		wn, err := toConn.Write(b[:rn])
		switch err {
		case io.EOF:
			return
		case nil:
		default:
			tflog.Error(reqCtx, fmt.Sprintf("failed to write to output connection: %s", err.Error()))
		}

		if wn != rn {
			tflog.Error(reqCtx, fmt.Sprintf("truncated write; %d < %d", wn, rn))
		}

		select {
		case <-sshContext.Done():
			return
		default:
		}
	}
}

func (r *TunnelResource) openLocalRelay(reqCtx, sshContext context.Context, data *ssh2vsock_types.EphemeralTunnelResourceData, sshClient *ssh.Client) (int, diag.Diagnostics) {
	lstn, err := net.Listen("tcp", "localhost:")
	if err != nil {
		r.cancelFunc()
		return 0, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to open a port on localhost",
				fmt.Sprintf("failed to open a port on localhost: %s", err.Error()),
			),
		}
	}

	go func() {
		<-sshContext.Done()
		if err := lstn.Close(); err != nil {
			tflog.Error(reqCtx, fmt.Sprintf("failed to close local relay port: %s", err.Error()))
		}
	}()

	_, localPort, err := net.SplitHostPort(lstn.Addr().String())
	if err != nil {
		r.cancelFunc()
		return 0, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to parse local listen address to get the random port",
				fmt.Sprintf("failed to parse local listen address %q to get the random port: %s", lstn.Addr().String(), err.Error()),
			),
		}
	}

	// Handle new TCP requests
	go func() {
		for {
			localConn, err := lstn.Accept()
			if err != nil {
				tflog.Error(reqCtx, fmt.Sprintf("failed to accept new connections: %s", err.Error()))
				return
			}

			// Handle individual new connections
			go func() {
				tflog.Debug(reqCtx, fmt.Sprintf("handling new connection from %s", localConn.LocalAddr().String()))
				loopbackAddress := fmt.Sprintf("localhost:%d", data.GuestPort())
				tunnelConn, err := sshClient.DialContext(sshContext, "tcp", loopbackAddress)
				if err != nil {
					tflog.Error(reqCtx, fmt.Sprintf("failed to dial to loopback address %q: %s", loopbackAddress, err.Error()))
					return
				}

				// Copy traffic both ways. We don't simply use io.Copy because we need to be aware of context cancellation
				go handleTrafficCopy(reqCtx, sshContext, localConn, tunnelConn)
				go handleTrafficCopy(reqCtx, sshContext, tunnelConn, localConn)
			}()

			// We should terminate on accept returning an error, but just to be extra safe, we also check if the context is cancelled too
			select {
			case <-sshContext.Done():
				return
			default:
			}
		}
	}()

	iLocalPort, err := strconv.Atoi(localPort)
	if err != nil {
		return 0, diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to convert port returned by listen",
				fmt.Sprintf("failed to convert port returned by listen %q: %s", localPort, err.Error()),
			),
		}
	}
	return iLocalPort, nil
}

func (r *TunnelResource) returnUnknown(reqCtx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	var configData terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(reqCtx, &configData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	configData.ListenPort = basetypes.NewInt32Unknown()
	if diags := resp.Result.Set(reqCtx, &configData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (r *TunnelResource) Open(reqCtx context.Context, req ephemeral.OpenRequest, resp *ephemeral.OpenResponse) {
	resData, unknown, diags := ssh2vsock_types.TunnelEphemeralResourceFromTFConfig(reqCtx, req.Config)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if unknown {
		r.returnUnknown(reqCtx, req, resp)
		return
	}

	if unknown, diags := resData.MergeProviderData(reqCtx, r.providerData); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	} else if unknown {
		r.returnUnknown(reqCtx, req, resp)
		return
	}

	// This check is NOT redundant with the checks implemented with ephemeral.EphemeralResourceWithValidateConfig because these checks benefits from the provider config and the config inheritence
	if diags := resData.ValidateConfig(reqCtx); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	sshContext, cancelFunc := context.WithCancel(context.Background())
	r.cancelFunc = cancelFunc

	hypervisorSSHClient, diags := openHypervisorConnection(reqCtx, sshContext, resData)
	if diags.HasError() {
		r.cancelFunc()
		resp.Diagnostics.Append(diags...)
		return
	}

	guestSSHClient, diags := openGuestConnection(reqCtx, sshContext, hypervisorSSHClient, resData, resData, nil)
	if diags.HasError() {
		r.cancelFunc()
		resp.Diagnostics.Append(diags...)
		return
	}

	localPort, diags := r.openLocalRelay(reqCtx, sshContext, resData, guestSSHClient)
	if diags.HasError() {
		r.cancelFunc()
		resp.Diagnostics.Append(diags...)
		return
	}

	var configData terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(reqCtx, &configData); diags.HasError() {
		r.cancelFunc()
		resp.Diagnostics.Append(diags...)
		return
	}
	configData.ListenPort = basetypes.NewInt32Value(int32(localPort))
	if diags := resp.Result.Set(reqCtx, &configData); diags.HasError() {
		r.cancelFunc()
		resp.Diagnostics.Append(diags...)
		return
	}
	tflog.Debug(reqCtx, fmt.Sprintf("opened local port %d to listen new connections", localPort))
}

func (r *TunnelResource) Close(ctx context.Context, req ephemeral.CloseRequest, resp *ephemeral.CloseResponse) {
	tflog.Debug(ctx, "Close called")
	if r != nil && r.cancelFunc != nil {
		r.cancelFunc()
		tflog.Debug(ctx, "cancelled context on ephemeral resource Close call")
	}
}

func (r *TunnelResource) ConfigValidators(_ context.Context) []ephemeral.ConfigValidator {
	return []ephemeral.ConfigValidator{
		&authn.Authn{},
		&sshfp.SSHFP{},
		&hostkeychecking.HostKey{},
		&sshprivkey.PrivateKey{},
		&fileexists.File{},
	}
}
