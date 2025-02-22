// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package sshprivkey

import (
	"fmt"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func writePrivateKey(filePath string) error {
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	pemPrivKey := []byte(`-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABB+IGsJe3
ceVkpz9LwbkKcDAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIFRIaJ7uuh6UYWHo
4DW6Gx7iu5BRK1x0AU+0jGsP0eB/AAAAkH5N0GBOKjFeibnnxDhC2zIoKayCvllvRtd7lJ
4bMwlF9gnlOOqt5OpwjZntVbceNb1YUZnnBZZta9bUn98GJ8qYHDLX1h4pOQYJxssGqh69
E6RIzabNeH+pvKN1UFgU6YtwBZy0roHuOydFR/LbUHBu4gDA6pTVfKNml6fRH4/aT5Rann
PNkr+t5ZKO6txviA==
-----END OPENSSH PRIVATE KEY-----
`)

	if n, err := f.Write(pemPrivKey); err != nil {
		return err
	} else if n != len(pemPrivKey) {
		return fmt.Errorf("truncated write: %d < %d", n, len(pemPrivKey))
	}

	return nil
}

func TestPrivateKeyOK(t *testing.T) {
	tmpdir := t.TempDir()
	filePath := path.Join(tmpdir, "privkey")
	if err := writePrivateKey(filePath); err != nil {
		t.Fatalf("failed to initialize private key: %s", err.Error())
	}

	privateKeyPath := basetypes.NewStringValue(filePath)
	privateKeyPassphrase := basetypes.NewStringValue("titi")

	if diags := ValidateConfig(privateKeyPath, privateKeyPassphrase); diags.HasError() {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestPrivateKeyWrongPassphrase(t *testing.T) {
	tmpdir := t.TempDir()
	filePath := path.Join(tmpdir, "privkey")
	if err := writePrivateKey(filePath); err != nil {
		t.Fatalf("failed to initialize private key: %s", err.Error())
	}

	privateKeyPath := basetypes.NewStringValue(filePath)
	privateKeyPassphrase := basetypes.NewStringValue("tutu")

	if diags := ValidateConfig(privateKeyPath, privateKeyPassphrase); !diags.HasError() {
		t.Fatal("unexpected success")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if diags[0].Detail() != "failed to parse private key with passphrase: x509: decryption password incorrect" {
		t.Fatalf("unexpected error: %v", diags)
	}
}

func TestPrivateKeyMissingFile(t *testing.T) {
	tmpdir := t.TempDir()
	filePath := path.Join(tmpdir, "privkey")

	privateKeyPath := basetypes.NewStringValue(filePath)
	privateKeyPassphrase := basetypes.NewStringValue("titi")

	if diags := ValidateConfig(privateKeyPath, privateKeyPassphrase); !diags.HasError() {
		t.Fatal("unexpected success")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if !strings.HasPrefix(diags[0].Detail(), "failed to open private key file") {
		t.Fatalf("unexpected error: %v", diags)
	}
}
