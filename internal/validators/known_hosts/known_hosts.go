// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package known_hosts

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"golang.org/x/crypto/ssh"
)

var _ validator.List = (*KnownHostsValidator)(nil)

type KnownHostsValidator struct{}

func (v *KnownHostsValidator) Description(ctx context.Context) string {
	return "KnownHostsValidator validates that the list only contains valid known host entries"
}

func (v *KnownHostsValidator) MarkdownDescription(ctx context.Context) string {
	return "KnownHostsValidator validates that the list only contains valid known host entries"
}

func (v *KnownHostsValidator) ValidateList(ctx context.Context, req validator.ListRequest, resp *validator.ListResponse) {
	value := req.ConfigValue

	knownHostCandidates := make([]types.String, 0, len(value.Elements()))
	if diags := value.ElementsAs(ctx, &knownHostCandidates, true); diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
	for _, knownHostCand := range knownHostCandidates {
		knownHostBytes := []byte(knownHostCand.ValueString())
		_, _, _, _, rest, err := ssh.ParseKnownHosts(knownHostBytes)
		if err != nil {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"invalid known host entry",
				fmt.Sprintf("invalid known host entry: failed to parse %q: %s", knownHostCand, err.Error()),
			)
			return
		}
		if len(rest) > 0 {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"invalid known host entry",
				fmt.Sprintf("invalid known host entry: remaining bytes %q", string(rest)),
			)
			return
		}
	}
}
