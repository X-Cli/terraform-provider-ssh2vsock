// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sshprivkey

import (
	"context"
	"fmt"
	"io"
	"os"

	ssh2vsock_types "github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/provider"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/terraform"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
)

var (
	_ ephemeral.ConfigValidator  = (*PrivateKey)(nil)
	_ datasource.ConfigValidator = (*PrivateKey)(nil)
	_ provider.ConfigValidator   = (*PrivateKey)(nil)
)

func ValidateConfig(privateKeyPath, privateKeyPassphrase types.String) diag.Diagnostics {
	if privateKeyPath.IsUnknown() || privateKeyPath.IsNull() || privateKeyPassphrase.IsUnknown() {
		return nil
	}

	pkPath := privateKeyPath.ValueString()
	f, err := os.Open(pkPath)
	if err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to open private key file",
				fmt.Sprintf("failed to open private key file: %s", err.Error()),
			),
		}
	}
	defer f.Close()
	pkBytes, err := io.ReadAll(io.LimitReader(f, ssh2vsock_types.PrivateKeyMaxSize))
	if err != nil {
		return diag.Diagnostics{
			diag.NewErrorDiagnostic(
				"failed to read private key file",
				fmt.Sprintf("failed to read private key file: %s", err.Error()),
			),
		}
	}

	if passphrase := privateKeyPassphrase.ValueString(); passphrase == "" {
		if _, err := ssh.ParsePrivateKey(pkBytes); err != nil {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"failed to parse private key",
					fmt.Sprintf("failed to parse private key: %s", err.Error()),
				),
			}
		}
	} else {
		if _, err := ssh.ParsePrivateKeyWithPassphrase(pkBytes, []byte(passphrase)); err != nil {
			return diag.Diagnostics{
				diag.NewErrorDiagnostic(
					"failed to parse private key with passphrase",
					fmt.Sprintf("failed to parse private key with passphrase: %s", err.Error()),
				),
			}
		}
	}
	return nil
}

type PrivateKey struct{}

func (v *PrivateKey) Description(_ context.Context) string {
	return "Validates that the private key file is readable and can be parsed as a SSH private key"
}

func (v *PrivateKey) MarkdownDescription(_ context.Context) string {
	return "Validates that the private key file is readable and can be parsed as a SSH private key"
}

func (v *PrivateKey) ValidateEphemeralResource(ctx context.Context, req ephemeral.ValidateConfigRequest, resp *ephemeral.ValidateConfigResponse) {
	var config terraform.EphemeralTunnelResourceDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.PrivateKeyPath, config.Hypervisor.PrivateKeyPassphrase); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
	if diags := ValidateConfig(config.Guest.PrivateKeyPath, config.Guest.PrivateKeyPassphrase); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (v *PrivateKey) ValidateDataSource(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config terraform.KnownHostModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.PrivateKeyPath, basetypes.NewStringNull()); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}

func (v *PrivateKey) ValidateProvider(ctx context.Context, req provider.ValidateConfigRequest, resp *provider.ValidateConfigResponse) {
	var config terraform.ProviderDataModel
	if diags := req.Config.Get(ctx, &config); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	if config.Hypervisor != nil {
		if diags := ValidateConfig(config.Hypervisor.PrivateKeyPath, config.Hypervisor.PrivateKeyPassphrase); diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}
	}
}
