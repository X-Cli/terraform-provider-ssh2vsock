// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package hostkeychecking

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestHostKeyCheckingOK(t *testing.T) {
	hostname := basetypes.NewStringValue("example.com")
	ignoreHostKey := basetypes.NewBoolValue(true)
	knownHostList := basetypes.NewListNull(types.StringType)
	knownHostFile := basetypes.NewStringNull()
	useSSHFP := basetypes.NewBoolNull()

	if diags := ValidateConfig(hostname, ignoreHostKey, knownHostList, knownHostFile, useSSHFP); diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestHostKeyCheckingHostnameMissing(t *testing.T) {
	hostname := basetypes.NewStringNull()
	ignoreHostKey := basetypes.NewBoolNull()
	knownHostList := basetypes.NewListNull(types.StringType)
	knownHostFile := basetypes.NewStringValue("toto")
	useSSHFP := basetypes.NewBoolNull()

	if diags := ValidateConfig(hostname, ignoreHostKey, knownHostList, knownHostFile, useSSHFP); !diags.HasError() {
		t.Fatal("unexpected success")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if diags[0].Detail() == "invalid configuration: hostname is required if some host key verification is performed for the guest invalid configuration" {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestHostKeyCheckingConflict(t *testing.T) {
	hostname := basetypes.NewStringValue("example.com")
	ignoreHostKey := basetypes.NewBoolValue(true)
	knownHostList := basetypes.NewListNull(types.StringType)
	knownHostFile := basetypes.NewStringNull()
	useSSHFP := basetypes.NewBoolValue(true)

	if diags := ValidateConfig(hostname, ignoreHostKey, knownHostList, knownHostFile, useSSHFP); !diags.HasError() {
		t.Fatal("unexpected success")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if !strings.HasPrefix(diags[0].Detail(), "invalid configuration: conflicting host key verification options for the guest") {
		t.Fatalf("unexpected error: %v", diags)
	}
}
