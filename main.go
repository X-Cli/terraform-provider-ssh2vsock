// Copyright (c) HashiCorp, Inc.

package main

import (
	"context"
	"log"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var (
	version string = "dev"
)

func main() {
	opts := providerserver.ServeOpts{
		Address:         "registry.terraform.io/x-cli/ssh2vsock",
		ProtocolVersion: 6,
	}
	err := providerserver.Serve(context.Background(), provider.New(version), opts)

	if err != nil {
		log.Fatal(err.Error())
	}
}
