// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sha1salt

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/function"
)

var (
	_ function.StringParameterValidator = (*SHA1SaltValidator)(nil)
)

type SHA1SaltValidator struct{}

func (v *SHA1SaltValidator) ValidateParameterString(ctx context.Context, req function.StringParameterValidatorRequest, resp *function.StringParameterValidatorResponse) {
	if req.Value.IsUnknown() || req.Value.IsNull() {
		return
	}

	decodedSalt, err := base64.StdEncoding.DecodeString(req.Value.ValueString())
	if err != nil {
		resp.Error = &function.FuncError{
			FunctionArgument: &req.ArgumentPosition,
			Text:             fmt.Sprintf("failed to decode argument using base64 standard decoder: %s", err.Error()),
		}
		return
	}

	if len(decodedSalt) != sha1.Size {
		resp.Error = &function.FuncError{
			FunctionArgument: &req.ArgumentPosition,
			Text:             fmt.Sprintf("invalid salt length: expected a %d bytes value", sha1.Size),
		}
		return
	}
}
