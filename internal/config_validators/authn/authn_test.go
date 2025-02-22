// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package authn

import (
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestValidatePasswordOnly(t *testing.T) {
	password := basetypes.NewStringValue("toto")
	privateKeyPath := basetypes.NewStringNull()
	privateKeyPassphrase := basetypes.NewStringNull()
	useAgent := basetypes.NewBoolNull()
	attributeName := "pouet"

	diags := ValidateConfig(password, privateKeyPath, privateKeyPassphrase, useAgent, attributeName)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestValidatePrivateKeyOnly(t *testing.T) {
	password := basetypes.NewStringNull()
	privateKeyPath := basetypes.NewStringValue("toto")
	privateKeyPassphrase := basetypes.NewStringNull()
	useAgent := basetypes.NewBoolNull()
	attributeName := "pouet"

	diags := ValidateConfig(password, privateKeyPath, privateKeyPassphrase, useAgent, attributeName)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestValidatePrivateKeyWithPassphraseOnly(t *testing.T) {
	password := basetypes.NewStringNull()
	privateKeyPath := basetypes.NewStringValue("toto")
	privateKeyPassphrase := basetypes.NewStringValue("titi")
	useAgent := basetypes.NewBoolNull()
	attributeName := "pouet"

	diags := ValidateConfig(password, privateKeyPath, privateKeyPassphrase, useAgent, attributeName)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestValidateUseAgentOnly(t *testing.T) {
	password := basetypes.NewStringNull()
	privateKeyPath := basetypes.NewStringNull()
	privateKeyPassphrase := basetypes.NewStringNull()
	useAgent := basetypes.NewBoolValue(true)
	attributeName := "pouet"

	diags := ValidateConfig(password, privateKeyPath, privateKeyPassphrase, useAgent, attributeName)
	if diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestValidateTwoAuthnPasswordAgent(t *testing.T) {
	password := basetypes.NewStringValue("toto")
	privateKeyPath := basetypes.NewStringNull()
	privateKeyPassphrase := basetypes.NewStringNull()
	useAgent := basetypes.NewBoolValue(true)
	attributeName := "pouet"

	diags := ValidateConfig(password, privateKeyPath, privateKeyPassphrase, useAgent, attributeName)
	if !diags.HasError() {
		t.Fatal("unexpected success")
	}
	if len(diags) != 1 {
		t.Fatalf("unexpected error count: %d", len(diags))
	}
	if !strings.HasPrefix(diags[0].Detail(), "too many authentication mechanism defined for the pouet") {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestValidateTwoAuthnPasswordPrivateKey(t *testing.T) {
	password := basetypes.NewStringValue("toto")
	privateKeyPath := basetypes.NewStringValue("titi")
	privateKeyPassphrase := basetypes.NewStringNull()
	useAgent := basetypes.NewBoolNull()
	attributeName := "pouet"

	diags := ValidateConfig(password, privateKeyPath, privateKeyPassphrase, useAgent, attributeName)
	if !diags.HasError() {
		t.Fatal("unexpected success")
	}
	if len(diags) != 1 {
		t.Fatalf("unexpected error count: %d", len(diags))
	}
	if !strings.HasPrefix(diags[0].Detail(), "too many authentication mechanism defined for the pouet") {
		t.Fatalf("unexpected error: %v", diags)
	}
}
