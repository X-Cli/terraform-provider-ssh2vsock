// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sha1salt

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestValidSalt(t *testing.T) {
	var v SHA1SaltValidator
	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 0,
		Value:            basetypes.NewStringValue("rdtCugQJct7YBsBmjOUmz4NIK3Y="),
	}
	var resp function.StringParameterValidatorResponse
	v.ValidateParameterString(context.Background(), req, &resp)

	if resp.Error != nil {
		t.Fatalf("unexpected error: %s", resp.Error.Text)
	}
}

func TestInvalidSalt(t *testing.T) {
	var v SHA1SaltValidator
	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 0,
		Value:            basetypes.NewStringValue("Bonjour!"),
	}
	var resp function.StringParameterValidatorResponse
	v.ValidateParameterString(context.Background(), req, &resp)

	if resp.Error == nil {
		t.Fatal("unexpected success")
	} else if resp.Error.FunctionArgument == nil {
		t.Fatal("missing function argument specifier")
	} else if i := *resp.Error.FunctionArgument; i != 0 {
		t.Fatalf("unexpected function argument: %d", i)
	} else if !strings.HasPrefix(resp.Error.Text, "failed to decode argument using base64 standard decoder") {
		t.Fatalf("unexpected error: %s", resp.Error.Text)
	}
}

func TestTooLongSalt(t *testing.T) {
	var v SHA1SaltValidator
	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 0,
		Value:            basetypes.NewStringValue("+lRj5sFUOGFn5YX2+gaqBx1RRi8pDZWfrCSbqrqOuGA="),
	}
	var resp function.StringParameterValidatorResponse
	v.ValidateParameterString(context.Background(), req, &resp)

	if resp.Error == nil {
		t.Fatal("unexpected success")
	} else if resp.Error.FunctionArgument == nil {
		t.Fatal("missing function argument specifier")
	} else if i := *resp.Error.FunctionArgument; i != 0 {
		t.Fatalf("unexpected function argument: %d", i)
	} else if !strings.HasPrefix(resp.Error.Text, "invalid salt length") {
		t.Fatalf("unexpected error: %s", resp.Error.Text)
	}
}

func TestTooShortSalt(t *testing.T) {
	var v SHA1SaltValidator
	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 0,
		Value:            basetypes.NewStringValue("y3GDDiHKqCeL9vcwiZrqdA=="),
	}
	var resp function.StringParameterValidatorResponse
	v.ValidateParameterString(context.Background(), req, &resp)

	if resp.Error == nil {
		t.Fatal("unexpected success")
	} else if resp.Error.FunctionArgument == nil {
		t.Fatal("missing function argument specifier")
	} else if i := *resp.Error.FunctionArgument; i != 0 {
		t.Fatalf("unexpected function argument: %d", i)
	} else if !strings.HasPrefix(resp.Error.Text, "invalid salt length") {
		t.Fatalf("unexpected error: %s", resp.Error.Text)
	}
}
