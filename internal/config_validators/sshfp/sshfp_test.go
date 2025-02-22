// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sshfp

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestSSHFPOK(t *testing.T) {
	hostname := basetypes.NewStringValue("example.com")
	useSSHFP := basetypes.NewBoolValue(true)
	dnsResolver := basetypes.NewStringValue("127.0.0.1:53")
	attributeName := "toto"

	if diags := ValidateConfig(context.Background(), hostname, useSSHFP, dnsResolver, attributeName); diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestSSHFPNoHostname(t *testing.T) {
	hostname := basetypes.NewStringNull()
	useSSHFP := basetypes.NewBoolValue(true)
	dnsResolver := basetypes.NewStringValue("127.0.0.1:53")
	attributeName := "toto"

	if diags := ValidateConfig(context.Background(), hostname, useSSHFP, dnsResolver, attributeName); !diags.HasError() {
		t.Fatal("uenxpected error")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if d := diags[0].Detail(); d != "invalid toto hostname value: hypervisor hostname is required" {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestSSHFPHostnameIsIPAddress(t *testing.T) {
	hostname := basetypes.NewStringValue("192.0.2.1")
	useSSHFP := basetypes.NewBoolValue(true)
	dnsResolver := basetypes.NewStringValue("127.0.0.1:53")
	attributeName := "toto"

	if diags := ValidateConfig(context.Background(), hostname, useSSHFP, dnsResolver, attributeName); !diags.HasError() {
		t.Fatal("uenxpected error")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if diags[0].Detail() != "invalid toto hostname value: hypervisor hostname parameter is an IP address but SSHFP is used to fetch the SSHFP records. These records cannot be retrieved for IP addresses" {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestSSHFPMissingDNSResolver(t *testing.T) {
	hostname := basetypes.NewStringValue("example.com")
	useSSHFP := basetypes.NewBoolValue(true)
	dnsResolver := basetypes.NewStringNull()
	attributeName := "toto"

	if diags := ValidateConfig(context.Background(), hostname, useSSHFP, dnsResolver, attributeName); !diags.HasError() {
		t.Fatal("uenxpected error")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if diags[0].Detail() != "invalid SSHFP configuration for the toto: SSHFP is requested but no DNS server was specified" {
		t.Fatalf("unexpected error: %v", diags)
	}
}
