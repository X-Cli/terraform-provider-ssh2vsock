// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package terraform

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type KnownHostHypervisorDataModel struct {
	Hostname           types.String `tfsdk:"hostname"`
	Port               types.Int32  `tfsdk:"port"`
	Username           types.String `tfsdk:"username"`
	PrivateKeyPath     types.String `tfsdk:"ssh_private_key"`
	UseAgent           types.Bool   `tfsdk:"ssh_use_agent"`
	AgentSockPath      types.String `tfsdk:"ssh_agent_sock"`
	KnownHosts         types.List   `tfsdk:"known_hosts"`
	KnownHostsFile     types.String `tfsdk:"known_hosts_file"`
	UseSSHFP           types.Bool   `tfsdk:"use_sshfp"`
	DNSRecursiveServer types.String `tfsdk:"dns_resolver"`
	CAFile             types.String `tfsdk:"ca_file"`
}

type KnownHostGuestDataModel struct {
	CID  types.Int32 `tfsdk:"cid"`
	Port types.Int32 `tfsdk:"port"`
}

type KnownHostModel struct {
	Hypervisor       *KnownHostHypervisorDataModel `tfsdk:"hypervisor"`
	Guest            KnownHostGuestDataModel       `tfsdk:"guest"`
	RSAKnownHost     types.String                  `tfsdk:"rsa_known_host"`
	ECDSAKnownHost   types.String                  `tfsdk:"ecdsa_known_host"`
	ED25519KnownHost types.String                  `tfsdk:"ed25519_known_host"`
}
