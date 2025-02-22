// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package fileexists

import (
	"context"
	"fmt"
	"os"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.ConfigValidator  = (*File)(nil)
	_ datasource.ConfigValidator = (*File)(nil)
	_ provider.ConfigValidator   = (*File)(nil)
)

func ValidateConfig(filenames ...types.String) diag.Diagnostics {
	for _, filename := range filenames {
		if filename.IsUnknown() || filename.IsNull() {
			return nil
		}
		_, err := os.Stat(filename.ValueString())
		if err != nil {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"missing file",
					fmt.Sprintf("missing file: cannot stat file %s: %s", filename.ValueString(), err.Error()),
				),
			}
		}
	}
	return nil
}

type File struct{}

func (v *File) Description(_ context.Context) string {
	return "Validates that the files exist"
}

func (v *File) MarkdownDescription(_ context.Context) string {
	return "Validates that the files exist"
}

func (v *File) ValidateEphemeralResource(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var config terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.AgentSockPath, config.Hypervisor.KnownHostsFile, config.Hypervisor.CAFile); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
	if diags := ValidateConfig(config.Guest.AgentSockPath, config.Guest.KnownHostsFile, config.Guest.CAFile); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (v *File) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config terraform.KnownHostModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.AgentSockPath, config.Hypervisor.KnownHostsFile, config.Hypervisor.CAFile); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}

func (v *File) ValidateProvider(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var config terraform.ProviderDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.AgentSockPath, config.Hypervisor.KnownHostsFile, config.Hypervisor.CAFile); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}
