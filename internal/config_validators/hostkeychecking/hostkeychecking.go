// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package hostkeychecking

import (
	"context"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.ConfigValidator = (*HostKey)(nil)
)

func ValidateConfig(hostname types.String, ignoreHostKey types.Bool, knownHosts types.List, knownHostsFile types.String, useSSHFP types.Bool) diag.Diagnostics {
	if !ignoreHostKey.IsUnknown() && !hostname.IsUnknown() {
		if !ignoreHostKey.ValueBool() && hostname.ValueString() == "" {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"invalid configuration",
					"invalid configuration: hostname is required if some host key verification is performed for the guest",
				),
			}
		}
	}

	if !ignoreHostKey.IsUnknown() && !knownHosts.IsUnknown() && !knownHostsFile.IsUnknown() && !useSSHFP.IsUnknown() {
		if ignoreHostKey.ValueBool() && (len(knownHosts.Elements()) > 0 || knownHostsFile.ValueString() != "" || useSSHFP.ValueBool()) {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"invalid configuration",
					"invalid configuration: conflicting host key verification options for the guest: if the host key is to be ignored, no other host key verification mechanism must be specified",
				),
			}
		}
	}

	return nil
}

type HostKey struct{}

func (v *HostKey) Description(_ context.Context) string {
	return "Validates the consistency of host key verification options"
}

func (v *HostKey) MarkdownDescription(_ context.Context) string {
	return "Validates the consistency of host key verification options"
}

func (v *HostKey) ValidateEphemeralResource(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var config terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if diags := ValidateConfig(config.Guest.Hostname, config.Guest.IgnoreHostKey, config.Guest.KnownHosts, config.Guest.KnownHostsFile, config.Guest.UseSSHFP); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}
