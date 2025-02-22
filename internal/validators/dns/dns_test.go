// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package dns

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestValidateDNSName(t *testing.T) {
	var v DNSValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue("www.example.com"),
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

func TestValidateNotDNSName(t *testing.T) {
	var v DNSValidator

	req := validator.StringRequest{
		Path:           path.Root("test"),
		PathExpression: path.MatchRoot("test"),
		Config:         tfsdk.Config{},
		ConfigValue:    basetypes.NewStringValue(strings.Repeat("a", 257)),
	}
	var resp validator.StringResponse

	v.ValidateString(context.Background(), req, &resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("should have returned an error")
	} else if ec := resp.Diagnostics.ErrorsCount(); ec != 1 {
		t.Fatalf("incorrect error count: %d; expected 1", ec)
	}
}

func TestValidateNull(t *testing.T) {
	var v DNSValidator

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

func TestValidateDNSNameParameter(t *testing.T) {
	var v DNSStringParameterValidator

	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 1,
		Value:            basetypes.NewStringValue("www.example.com"),
	}
	var resp function.StringParameterValidatorResponse

	v.ValidateParameterString(context.Background(), req, &resp)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Text)
	}
}

func TestValidateNotDNSNameParameter(t *testing.T) {
	var v DNSStringParameterValidator

	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 1,
		Value:            basetypes.NewStringValue(strings.Repeat("a", 257)),
	}
	var resp function.StringParameterValidatorResponse

	v.ValidateParameterString(context.Background(), req, &resp)

	if resp.Error == nil {
		t.Fatal("unexpected success")
	} else if !strings.HasPrefix(resp.Error.Text, "invalid domain name") {
		t.Fatalf("unexpected error: %s", resp.Error.Text)
	} else if resp.Error.FunctionArgument == nil {
		t.Fatal("missing function argument value")
	} else if *resp.Error.FunctionArgument != 1 {
		t.Fatalf("unexpected function argument value: %d", *resp.Error.FunctionArgument)
	}
}
