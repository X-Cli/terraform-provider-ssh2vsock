// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package terraform

import (
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type HypervisorModel struct {
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

func HypervisorModelAttributeTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"hostname":                   types.StringType,
		"port":                       types.Int32Type,
		"username":                   types.StringType,
		"password":                   types.StringType,
		"ssh_private_key":            types.StringType,
		"ssh_private_key_passphrase": types.StringType,
		"ssh_use_agent":              types.BoolType,
		"ssh_agent_sock":             types.StringType,
		"known_hosts":                types.ListType{ElemType: types.StringType},
		"known_hosts_file":           types.StringType,
		"use_sshfp":                  types.BoolType,
		"dns_resolver":               types.StringType,
		"ca_file":                    types.StringType,
	}
}
