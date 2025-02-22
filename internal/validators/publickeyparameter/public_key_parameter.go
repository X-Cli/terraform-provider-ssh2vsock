// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package publickeyparameter

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"golang.org/x/crypto/ssh"
)

var (
	_ function.StringParameterValidator = (*PublicKeyParameterValidator)(nil)
)

type PublicKeyParameterValidator struct{}

func (pkpv *PublicKeyParameterValidator) ValidateParameterString(ctx context.Context, req function.StringParameterValidatorRequest, resp *function.StringParameterValidatorResponse) {
	candidate := req.Value
	candidateBytes, err := base64.StdEncoding.DecodeString(candidate.ValueString())
	if err != nil {
		resp.Error = &function.FuncError{
			FunctionArgument: &req.ArgumentPosition,
			Text:             fmt.Sprintf("failed to decode parameter as base64: %s", err.Error()),
		}
		return
	}
	if _, err := ssh.ParsePublicKey(candidateBytes); err != nil {
		resp.Error = &function.FuncError{
			FunctionArgument: &req.ArgumentPosition,
			Text:             fmt.Sprintf("failed to parse parameter as a public key: %s", err.Error()),
		}
	}
}
