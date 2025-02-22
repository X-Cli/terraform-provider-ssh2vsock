// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package ip

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestIP4Validation(t *testing.T) {
	var v IPValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("192.168.0.1"),
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

// TestIP4ValidationV6Expected works because v4 addresses can be converted to v6 seamlessly; the opposite is not true
func TestIP4ValidationV6Expected(t *testing.T) {
	v := IPValidator{
		ValidFamily: ValidateIPv6,
	}

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("192.168.0.1"),
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

func TestIP6Validation(t *testing.T) {
	var v IPValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("2001:db8::1"),
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

func TestIP6ValidationV4Expected(t *testing.T) {
	v := IPValidator{
		ValidFamily: ValidateIPv4,
	}

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("2001:db8::1"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestNotIPValidation(t *testing.T) {
	var v IPValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("www.example.com"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestAnyIPValidation(t *testing.T) {
	v := IPValidator{
		ValidFamily: ValidateIPv4 | ValidateIPv6,
	}

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("192.168.0.1"),
	}

	var resp validator.StringResponse
	v.ValidateString(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}

	req = validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("2001:db8::1"),
	}

	resp = validator.StringResponse{}
	v.ValidateString(context.Background(), req, &resp)

	if resp.Diagnostics.HasError() {
		for _, err := range resp.Diagnostics.Errors() {
			t.Errorf("diagnostic error: %s", err.Detail())
		}
		t.Fatalf("found %d errors", resp.Diagnostics.ErrorsCount())
	}
}

func TestNullIPValidation(t *testing.T) {
	v := IPValidator{
		ValidFamily: ValidateIPv4 | ValidateIPv6,
	}

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
