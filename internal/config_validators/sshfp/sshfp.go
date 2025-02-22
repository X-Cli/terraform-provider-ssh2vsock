// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sshfp

import (
	"context"
	"fmt"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/ip"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ ephemeral.ConfigValidator  = (*SSHFP)(nil)
	_ datasource.ConfigValidator = (*SSHFP)(nil)
	_ provider.ConfigValidator   = (*SSHFP)(nil)
)

func ValidateConfig(ctx context.Context, hostname types.String, useSSHFP types.Bool, dnsResolver types.String, attributeName string) diag.Diagnostics {
	if !hostname.IsUnknown() && !useSSHFP.IsUnknown() {
		if hostname.IsNull() {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					fmt.Sprintf("invalid %s hostname value", attributeName),
					fmt.Sprintf("invalid %s hostname value: hypervisor hostname is required", attributeName),
				),
			}
		}

		if useSSHFP.ValueBool() {
			var v ip.IPValidator
			vReq := validator.StringRequest{
				Path:           path.Empty(),
				PathExpression: path.MatchRelative(),
				ConfigValue:    hostname,
			}
			var vResp validator.StringResponse
			v.ValidateString(ctx, vReq, &vResp)
			if !vResp.Diagnostics.HasError() {
				return diag.Diagnostics{
					diag.NewErrorDiagnostic(
						fmt.Sprintf("invalid %s hostname value", attributeName),
						fmt.Sprintf("invalid %s hostname value: hypervisor hostname parameter is an IP address but SSHFP is used to fetch the SSHFP records. These records cannot be retrieved for IP addresses", attributeName),
					),
				}
			}
		}
	}

	if !useSSHFP.IsUnknown() || !dnsResolver.IsUnknown() {
		if useSSHFP.ValueBool() && dnsResolver.ValueString() == "" {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					fmt.Sprintf("invalid SSHFP configuration for the %s", attributeName),
					fmt.Sprintf("invalid SSHFP configuration for the %s: SSHFP is requested but no DNS server was specified", attributeName),
				),
			}
		}
	}
	return nil
}

type SSHFP struct{}

func (v *SSHFP) Description(_ context.Context) string {
	return "Validates SSHFP configuration consistency"
}

func (v *SSHFP) MarkdownDescription(_ context.Context) string {
	return "Validates SSHFP configuration consistency"
}

func (v *SSHFP) ValidateEphemeralResource(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var config terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(ctx, config.Hypervisor.Hostname, config.Hypervisor.UseSSHFP, config.Hypervisor.DNSRecursiveServer, "hypervisor"); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
	if diags := ValidateConfig(ctx, config.Guest.Hostname, config.Guest.UseSSHFP, config.Guest.DNSRecursiveServer, "guest"); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (v *SSHFP) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config terraform.KnownHostModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(ctx, config.Hypervisor.Hostname, config.Hypervisor.UseSSHFP, config.Hypervisor.DNSRecursiveServer, "hypervisor"); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}

func (v *SSHFP) ValidateProvider(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var config terraform.ProviderDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(ctx, config.Hypervisor.Hostname, config.Hypervisor.UseSSHFP, config.Hypervisor.DNSRecursiveServer, "hypervisor"); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}
