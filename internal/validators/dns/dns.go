// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package dns

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/miekg/dns"
)

var (
	_ validator.String                  = (*DNSValidator)(nil)
	_ function.StringParameterValidator = (*DNSStringParameterValidator)(nil)
)

type DNSValidator struct{}

func (v *DNSValidator) Description(ctx context.Context) string {
	return "DNSValidator validates that the value is a valid domain name"
}

func (v *DNSValidator) MarkdownDescription(ctx context.Context) string {
	return "DNSValidator validates that the value is a valid domain name"
}

func (v *DNSValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue
	if value.IsUnknown() || value.IsNull() {
		return
	}

	dnCandidate := value.ValueString()
	if _, ok := dns.IsDomainName(dnCandidate); !ok {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"invalid domain name",
			fmt.Sprintf("%q failed to be parsed as a valid domain name", dnCandidate),
		)
	}
}

type DNSStringParameterValidator struct{}

func (v *DNSStringParameterValidator) ValidateParameterString(ctx context.Context, req function.StringParameterValidatorRequest, resp *function.StringParameterValidatorResponse) {
	value := req.Value
	if value.IsUnknown() || value.IsNull() {
		return
	}
	dnCandidate := value.ValueString()
	if _, ok := dns.IsDomainName(dnCandidate); !ok {
		resp.Error = &function.FuncError{
			FunctionArgument: &req.ArgumentPosition,
			Text:             fmt.Sprintf("invalid domain name: %s", dnCandidate),
		}
	}
}
