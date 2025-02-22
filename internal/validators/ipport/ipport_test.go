// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package ipport

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestIP4PortValidation(t *testing.T) {
	var v IPPortValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("192.168.0.1:80"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestIP4PortValidationMissingPort(t *testing.T) {
	var v IPPortValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("192.168.0.1:"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestIP6PortValidation(t *testing.T) {
	var v IPPortValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("[2001:db8::1]:80"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestIPPortValidationNoIP(t *testing.T) {
	var v IPPortValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue(":80"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestIPPortValidationNullValue(t *testing.T) {
	var v IPPortValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringNull(),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}
