// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package known_hosts

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestKnownHostsValidation(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{
		basetypes.NewStringValue(`git.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCU`),
		basetypes.NewStringValue(`proxmox.broken-by-design.fr ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOFug4dm3KRbjUISJ2K9/KFyHAHBACJtOohWG29OCh7KlTjGQLozMd8+QBrNG8xc9K3lm+b58qPh+mbdhEJJ/no=`),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestNoKnownHostValidation(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestNullKnownHostListValidation(t *testing.T) {
	var v KnownHostsValidator

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewListNull(types.StringType),
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestHashedKnownHostsValidation(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{
		basetypes.NewStringValue(`|1|rdtCugQJct7YBsBmjOUmz4NIK3Y=|scHvnwDNXO8mHrHCChJhZ4pC8tM= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCU`),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestKnownHostsValidationTrailingBytes(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{
		basetypes.NewStringValue(`git.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCUdeadcafe`),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestKnownHostsValidationTrailingEntry(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{
		basetypes.NewStringValue(`git.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCU
git.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCU`),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestKnownHostsValidationNoBase64(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{
		basetypes.NewStringValue(`git.broken-by-design.fr ssh-ed25519 !AAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCU`),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestKnownHostsValidationBonjour(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.StringType, []attr.Value{
		basetypes.NewStringValue(`Bonjour`),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestKnownHostsValidationInt32List(t *testing.T) {
	var v KnownHostsValidator

	knownHostValues, diags := basetypes.NewListValue(types.Int32Type, []attr.Value{
		basetypes.NewInt32Value(0),
	})
	if diags.HasError() {
		for _, err := range diags.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatal("failed to initialize test")
	}

	req := validator.ListRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    knownHostValues,
	}

	var resp validator.ListResponse
	v.ValidateList(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}
