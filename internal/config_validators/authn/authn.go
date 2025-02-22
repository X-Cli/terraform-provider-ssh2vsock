// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package authn

import (
	"context"
	"fmt"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

var (
	_ ephemeral.ConfigValidator  = (*Authn)(nil)
	_ datasource.ConfigValidator = (*Authn)(nil)
	_ provider.ConfigValidator   = (*Authn)(nil)
)

// ValidateConfig validates that none or at most one authentication mechanism was specified for the guest
func ValidateConfig(password, privateKeyPath, privateKeyPassphrase types.String, useAgent types.Bool, attributeName string) diag.Diagnostics {
	if !password.IsUnknown() && !privateKeyPath.IsUnknown() && !useAgent.IsUnknown() {
		var count int
		if password.ValueString() != "" {
			count += 1
		}
		if privateKeyPath.ValueString() != "" {
			count += 1
		}
		if useAgent.ValueBool() {
			count += 1
		}
		if count >= 2 {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					fmt.Sprintf("too many authentication mechanism defined for the %s", attributeName),
					fmt.Sprintf("too many authentication mechanism defined for the %s: at most one should be defined", attributeName),
				),
			}
		}
	}

	if !privateKeyPath.IsUnknown() && !privateKeyPassphrase.IsUnknown() {
		if privateKeyPath.ValueString() == "" && privateKeyPassphrase.ValueString() != "" {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					fmt.Sprintf("inconsistent configuration for the %s", attributeName),
					fmt.Sprintf("inconsistent configuration: private key passphrase specified but missing private key path for the %s", attributeName),
				),
			}
		}
	}
	return nil
}

type Authn struct{}

func (v *Authn) Description(_ context.Context) string {
	return "Validates the authentication configuration"
}

func (v *Authn) MarkdownDescription(_ context.Context) string {
	return "Validates the authentication configuration"
}

func (v *Authn) ValidateEphemeralResource(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var config terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.Password, config.Hypervisor.PrivateKeyPath, config.Hypervisor.PrivateKeyPassphrase, config.Hypervisor.UseAgent, "hypervisor"); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}

	if diags := ValidateConfig(config.Guest.Password, config.Guest.PrivateKeyPath, config.Guest.PrivateKeyPassphrase, config.Guest.UseAgent, "guest"); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (v *Authn) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config terraform.KnownHostModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if config.Hypervisor != nil {
		if diags := ValidateConfig(basetypes.NewStringNull(), config.Hypervisor.PrivateKeyPath, basetypes.NewStringNull(), config.Hypervisor.UseAgent, "hypervisor"); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}

func (v *Authn) ValidateProvider(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var config terraform.ProviderDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.Password, config.Hypervisor.PrivateKeyPath, config.Hypervisor.PrivateKeyPassphrase, config.Hypervisor.UseAgent, "hypervisor"); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}
