// Copyright (c) Florian Maury
// SPDX-License-Identifier: BSD-2-Clause

package fileexists

import (
	"os"
	"path"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
)

func TestFileExists(t *testing.T) {
	tmpdir := t.TempDir()
	filePath := path.Join(tmpdir, "toto")
	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("failed to create file: %s", err.Error())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %s", err.Error())
	}

	filePathValue := basetypes.NewStringValue(filePath)
	if diags := ValidateConfig(filePathValue); diags.HasError() {
		t.Fatalf("unexpected error: %v", filePathValue)
	}
}

func TestFileMissing(t *testing.T) {
	tmpdir := t.TempDir()
	filePath := path.Join(tmpdir, "toto")

	filePathValue := basetypes.NewStringValue(filePath)
	if diags := ValidateConfig(filePathValue); !diags.HasError() {
		t.Fatal("unexpected success")
	} else if len(diags) != 1 {
		t.Fatalf("unexpected error: %v", diags)
	} else if !strings.HasPrefix(diags[0].Detail(), "missing file: cannot stat file") {
		t.Fatalf("unexpected error: %v", diags)
	}
}
