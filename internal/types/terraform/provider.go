// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package terraform

import "github.com/hashicorp/terraform-plugin-framework/types"

type HypervisorProviderDataModel struct {
	Hostname             types.String `tfsdk:"hostname"`
	Port                 types.Int32  `tfsdk:"port"`
	Username             types.String `tfsdk:"username"`
	Password             types.String `tfsdk:"password"`
	PrivateKeyPath       types.String `tfsdk:"ssh_private_key"`
	PrivateKeyPassphrase types.String `tfsdk:"ssh_private_key_passphrase"`
	UseAgent             types.Bool   `tfsdk:"ssh_use_agent"`
	AgentSockPath        types.String `tfsdk:"ssh_agent_sock"`
	KnownHosts           types.List   `tfsdk:"known_hosts"`
	KnownHostsFile       types.String `tfsdk:"known_hosts_file"`
	UseSSHFP             types.Bool   `tfsdk:"use_sshfp"`
	DNSRecursiveServer   types.String `tfsdk:"dns_resolver"`
	CAFile               types.String `tfsdk:"ca_file"`
}

type ProviderDataModel struct {
	Hypervisor *HypervisorProviderDataModel `tfsdk:"hypervisor"`
}
