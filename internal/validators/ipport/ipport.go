// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package ipport

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

var _ validator.String = (*IPPortValidator)(nil)

type IPPortValidator struct{}

func (v *IPPortValidator) Description(ctx context.Context) string {
	return "IPPortValidator validates that the value is a valid IP and port address"
}

func (v *IPPortValidator) MarkdownDescription(ctx context.Context) string {
	return "IPPortValidator validates that the value is a valid IP and port address"
}

func (v *IPPortValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	value := req.ConfigValue
	if value.IsUnknown() || value.IsNull() {
		return
	}
	address := value.ValueString()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"invalid address",
			fmt.Sprintf("invalid address: failed to split host and port in %q: %s", address, err.Error()),
		)
		return
	}

	iPort, err := strconv.Atoi(port)
	if err != nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"invalid port number",
			fmt.Sprintf("invalid port number: failed to parse %q as int: %s", port, err.Error()),
		)
		return
	}

	if iPort < 1 || iPort > 65535 {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"invalid port number range",
			fmt.Sprintf("invalid port number range: %d", iPort),
		)
		return
	}

	ip := net.ParseIP(host)
	if ip == nil {
		resp.Diagnostics.AddAttributeError(
			req.Path,
			"invalid IP address",
			fmt.Sprintf("invalid IP address: failed to parse address %q", host),
		)
		return
	}
}
