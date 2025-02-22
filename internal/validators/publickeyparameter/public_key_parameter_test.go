// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package publickeyparameter

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestValidateKeyOK(t *testing.T) {
	value := basetypes.NewStringValue("AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8")
	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 1,
		Value:            value,
	}
	var resp function.StringParameterValidatorResponse
	var validator PublicKeyParameterValidator
	validator.ValidateParameterString(context.Background(), req, &resp)
	if resp.Error != nil {
		t.Fatalf("failed to verify value: %s", resp.Error.Text)
	}
}

func TestValidateKeyInvalidBase64(t *testing.T) {
	value := basetypes.NewStringValue("Bonjour!")
	req := function.StringParameterValidatorRequest{
		ArgumentPosition: 1,
		Value:            value,
	}
	var resp function.StringParameterValidatorResponse
	var validator PublicKeyParameterValidator
	validator.ValidateParameterString(context.Background(), req, &resp)
	if resp.Error == nil {
		t.Fatal("unexpected success")
	} else if !strings.HasPrefix(resp.Error.Text, "failed to decode parameter as base64") {
		t.Fatalf("unexpected error message: %s", resp.Error.Text)
	} else if resp.Error.FunctionArgument == nil {
		t.Fatalf("unset function argument")
	} else if *resp.Error.FunctionArgument != 1 {
		t.Fatalf("unexpected function argument position: %d", *resp.Error.FunctionArgument)
	}
}
