// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/sshfp"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/publickeyparameter"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
)

var (
	_                          function.Function = (*SSHFPFunc)(nil)
	sshfpFuncRetAttributeTypes                   = map[string]attr.Type{
		"algorithm":   types.Int32Type,
		"type":        types.Int32Type,
		"fingerprint": types.StringType,
	}
)

type SSHFPFunc struct{}

func NewSSHFPFunc() function.Function {
	return &SSHFPFunc{}
}

func (f *SSHFPFunc) Metadata(ctx context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "make_sshfp"
}

func (f *SSHFPFunc) Definition(ctx context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: `Computes the SSHFP fingerprint of a SSH public key.`,
		MarkdownDescription: `The "make_sshfp" function computes the SSHFP record of the provided SSH public key.
Only the SHA256 fingerprint is generated, since SHA-1 is now obsolete.
`,
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:               "key",
				AllowNullValue:     false,
				AllowUnknownValues: true,
				MarkdownDescription: `The key argument is the SSH public key whose SSHFP record will be generated.
The input format is the SSH wire format of the public key, encoded using base64 standard encoding with padding.`,
				Validators: []function.StringParameterValidator{
					&publickeyparameter.PublicKeyParameterValidator{},
				},
			},
		},
		Return: function.ObjectReturn{
			AttributeTypes: sshfpFuncRetAttributeTypes,
		},
	}
}

func (f *SSHFPFunc) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var keyPos int64 = 0
	var key types.String

	if err := req.Arguments.Get(ctx, &key); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, err)
		return
	}

	if key.IsUnknown() {
		resp.Result = function.NewResultData(basetypes.NewObjectUnknown(sshfpFuncRetAttributeTypes))
		return
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key.ValueString())
	if err != nil {
		resp.Error = &function.FuncError{
			FunctionArgument: &keyPos,
			Text:             fmt.Sprintf("failed to decode argument as base64: %s", err.Error()),
		}
		return
	}

	pubKey, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		resp.Error = &function.FuncError{
			FunctionArgument: &keyPos,
			Text:             fmt.Sprintf("failed to parse argument as a SSH public key: %s", err.Error()),
		}
		return
	}

	sha2 := sha256.New()
	if _, err := sha2.Write(pubKey.Marshal()); err != nil {
		resp.Error = &function.FuncError{
			FunctionArgument: &keyPos,
			Text:             fmt.Sprintf("failed to add key to the hash: %s", err.Error()),
		}
		return
	}
	hash := sha2.Sum(nil)
	retValue, diags := basetypes.NewObjectValue(sshfpFuncRetAttributeTypes, map[string]attr.Value{
		"algorithm":   basetypes.NewInt32Value(int32(sshfp.KeyTypeToSSHFPAlgo[pubKey.Type()])),
		"type":        basetypes.NewInt32Value(2),
		"fingerprint": basetypes.NewStringValue(hex.EncodeToString(hash)),
	})
	if diags.HasError() {
		var errors *function.FuncError
		for _, diag := range diags.Errors() {
			errors = function.ConcatFuncErrors(errors, &function.FuncError{
				Text: diag.Detail(),
			})
		}
		resp.Error = errors
		return
	}
	resp.Result = function.NewResultData(retValue)
}
