// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package ip

import (
	"context"
	"fmt"
	"net"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type AddressFamily int

const (
	ValidateIPv4 AddressFamily = 1 << iota
	ValidateIPv6
)

var _ validator.String = (*IPValidator)(nil)

type IPValidator struct {
	ValidFamily AddressFamily
}

func (v *IPValidator) Description(ctx context.Context) string {
	switch v.ValidFamily {
	case ValidateIPv4:
		return "IPValidator validates that the value is a valid IPv4 address"
	case ValidateIPv6:
		return "IPValidator validates that the value is a valid IPv6 address"
	case ValidateIPv4 | ValidateIPv6:
		fallthrough
	default:
		return "IPValidator validates that the value is a valid IPv4 or IPv6 address"
	}
}

func (v *IPValidator) MarkdownDescription(ctx context.Context) string {
	switch v.ValidFamily {
	case ValidateIPv4:
		return "IPValidator validates that the value is a valid IPv4 address"
	case ValidateIPv6:
		return "IPValidator validates that the value is a valid IPv6 address"
	case ValidateIPv4 | ValidateIPv6:
		fallthrough
	default:
		return "IPValidator validates that the value is a valid IPv4 or IPv6 address"
	}
}

func (v *IPValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue
	if value.IsUnknown() || value.IsNull() {
		return
	}

	var acceptedFamily string
	switch v.ValidFamily {
	case ValidateIPv4:
		acceptedFamily = "IPv4"
	case ValidateIPv6:
		acceptedFamily = "IPv6"
	case ValidateIPv4 | ValidateIPv6:
		fallthrough
	default:
		acceptedFamily = "IPv4 or IPv6"
	}

	ipCandidate := value.ValueString()
	parsedAddress := net.ParseIP(ipCandidate)
	if parsedAddress == nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			fmt.Sprintf("invalid %s address", acceptedFamily),
			fmt.Sprintf("%q is not a valid %s address", ipCandidate, acceptedFamily),
		)
	}
	if v.ValidFamily == ValidateIPv4 {
		convertedIP := parsedAddress.To4()
		if convertedIP == nil {
			resp.Diagnostics.AddAttributeError(
				req.Path,
				"unacceptable IPv6 address",
				fmt.Sprintf("%q is a valid IPv6 address, but only IPv4 addresses are accepted for this parameter", ipCandidate),
			)
		}
	}
}
