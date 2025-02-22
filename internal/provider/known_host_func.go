// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package provider

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/dns"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/publickeyparameter"
	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/validators/sha1salt"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	_ function.Function = (*KnownHostFunc)(nil)
)

type KnownHostFunc struct{}

func NewKnownHostFunc() function.Function {
	return &KnownHostFunc{}
}

func (f *KnownHostFunc) Metadata(ctx context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "make_known_host"
}

func (f *KnownHostFunc) Definition(ctx context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Generates a known host entry",
		MarkdownDescription: `"make_known_host generates a known host entry using the specified arguments.
The generated entry can use the modern privacy preserving hostname hashing procedure if the "hash_salt" argument is not null.
`,
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:               "key",
				AllowNullValue:     false,
				AllowUnknownValues: true,
				MarkdownDescription: `The "key" argument specifies the SSH public key of the known host.
The key must be encoded in the SSH wire format for public keys and encoded using standard base64 encoding (with padding).`,
				Validators: []function.StringParameterValidator{
					&publickeyparameter.PublicKeyParameterValidator{},
				},
			},
			function.StringParameter{
				Name:               "hostname",
				AllowNullValue:     false,
				AllowUnknownValues: true,
				MarkdownDescription: `The "hostname" argument specifies the hostname of the known host.
This hostname will be included in the known host entry, either as provided or in a hashed format, depending on the nullity of the "hash_salt" argument.
`,
				Validators: []function.StringParameterValidator{
					&dns.DNSStringParameterValidator{},
				},
			},
			function.Int32Parameter{
				Name:                "port",
				AllowNullValue:      false,
				AllowUnknownValues:  true,
				MarkdownDescription: `The "port" argument specifies the port on which the known host SSH service listens.`,
			},
			function.StringParameter{
				Name:               "hash_salt",
				AllowNullValue:     true,
				AllowUnknownValues: true,
				MarkdownDescription: `The "hash_salt" argument specifies the salt to use if the known host hostname should be privacy protected.
If this argument is null, the hostname is not hashed.
If non-null, the value of this argument is expected to be a 20-byte value, encoded using standard base64 encoding (with padding).`,
				Validators: []function.StringParameterValidator{
					&sha1salt.SHA1SaltValidator{},
				},
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *KnownHostFunc) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var key types.String
	var hostname types.String
	var port types.Int32
	var hashSalt types.String

	var keyPos int64 = 0
	var portPos int64 = 2
	var saltPos int64 = 3

	if err := req.Arguments.Get(ctx, &key, &hostname, &port, &hashSalt); err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, err)
		return
	}

	if key.IsUnknown() || hostname.IsUnknown() || port.IsUnknown() || hashSalt.IsUnknown() {
		resp.Result = function.NewResultData(basetypes.NewStringUnknown())
		return
	}

	iPort := int(port.ValueInt32())
	if iPort < 1 || iPort > 65535 {
		resp.Error = function.ConcatFuncErrors(resp.Error, &function.FuncError{
			FunctionArgument: &portPos,
			Text:             "invalid port value: expected a value between 1 and 65535",
		})
		return
	}

	keyBytes, err := base64.StdEncoding.DecodeString(key.ValueString())
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, &function.FuncError{
			FunctionArgument: &keyPos,
			Text:             fmt.Sprintf("failed to decode base64 value parameter: %s", err.Error()),
		})
		return
	}

	pubKey, err := ssh.ParsePublicKey(keyBytes)
	if err != nil {
		resp.Error = function.ConcatFuncErrors(resp.Error, &function.FuncError{
			FunctionArgument: &keyPos,
			Text:             fmt.Sprintf("failed to parse parameter as a SSH public key: %s", err.Error()),
		})
		return
	}

	address := knownhosts.Normalize(fmt.Sprintf("%s:%d", hostname.ValueString(), iPort))
	if salt := hashSalt.ValueString(); salt != "" {
		rawSalt, err := base64.StdEncoding.DecodeString(salt)
		if err != nil {
			resp.Error = function.ConcatFuncErrors(resp.Error, &function.FuncError{
				FunctionArgument: &saltPos,
				Text:             fmt.Sprintf("failed to decode salt value: %s", err.Error()),
			})
		}
		hmacSha1 := hmac.New(sha1.New, rawSalt)
		hmacSha1.Write([]byte(address))
		mac := base64.StdEncoding.EncodeToString(hmacSha1.Sum(nil))
		address = fmt.Sprintf("|1|%s|%s", salt, mac)
	}

	resp.Result = function.NewResultData(basetypes.NewStringValue(knownhosts.Line([]string{address}, pubKey)))
}
