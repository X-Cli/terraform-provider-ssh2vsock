// Copyright (c) HashiCorp, Inc.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/X-Cli/terraform-provider-ssh2vsock/internal/provider"
	ssh2vsock_types "github.com/X-Cli/terraform-provider-ssh2vsock/internal/types/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"golang.org/x/crypto/ssh"
)

var (
	knownHostDataSourceKnownValuesStateChecks = []statecheck.StateCheck{
		statecheck.ExpectKnownValue(
			"data.ssh2vsock_known_host.testvm",
			tfjsonpath.New("ed25519_known_host"),
			knownvalue.StringExact("AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8"),
		),
		statecheck.ExpectKnownValue(
			"data.ssh2vsock_known_host.testvm",
			tfjsonpath.New("rsa_known_host"),
			knownvalue.StringExact("AAAAB3NzaC1yc2EAAAADAQABAAABgQDE2hO9V1jX0CchhqkpCliTOVh2Utaf3CAGDehpkugvdraJiXovzC60pq7f2BX6QAHFYuhxv327L7qQt8KMT01yQr/U79ubv5QH3MuLu9TScbhPUlRwPYC5StwjVP8yK7GN5FqbBLwXzYITYRIT5lbtu2ggHNdXZA1ZLSOqqvD9tCSd0qSPhHiOIBtLwnVofj9tsYM1NhX/LhcSs3EKNiFFu+THy/IP7LSu+m6urhvPBbt5EGoM4AzyjrfJh22VWnu68BdPXiSaxJVWbcIHC5Qy/GQ5+sAkGhWFnf+C+iWeXhR6cfnseuL/FXCH9ThGafew5kGjHVu7yWULaMHqVCJdv5hK7cxZUk9EwSAfd8bFCwFLwwNJgTJvvC6J7AoiXaeYGj2ET0Od2THiVG923gCwb9WF4Ug+VPc7r1ucZPqIEFaTzg4PHcJFVhPxqm+fvRoRq4ImgSSibBxGYmCe4HPqWHOt5qYTebffSwFdxF6ZcWr9QpGvjed8E99LDGY8/7s="),
		),
		statecheck.ExpectKnownValue(
			"data.ssh2vsock_known_host.testvm",
			tfjsonpath.New("ecdsa_known_host"),
			knownvalue.StringExact("AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDauUp4eAbyA3KgzkBo7+Qy5JB2qlbnpoSv/2J0cv2shpvcpMdB+c87N+GojYFmGhUAeDuJgOfWLgr4TVSO5V3o="),
		),
	}
)

func TestAccDataSourceUnknown(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"random": {
				Source: "hashicorp/random",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {}

resource "random_integer" "port" {
  min = 22
  max = 22
}

data "ssh2vsock_known_host" "testvm" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    port = random_integer.port.result
    username = "root"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
  guest = {
    cid = 113
    port = 22
  }
}`,
				ConfigStateChecks: knownHostDataSourceKnownValuesStateChecks,
			},
		},
	})
}

func TestAccDataSourceProviderUnknown(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"random": {
				Source: "hashicorp/random",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "random_integer" "port" {
  min = 22
  max = 22
}

provider "ssh2vsock" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    port = random_integer.port.result
    username = "root"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
}

data "ssh2vsock_known_host" "testvm" {
  depends_on = [random_integer.port]
  guest = {
    cid = 113
    port = 22
  }
}`,
				ConfigStateChecks: knownHostDataSourceKnownValuesStateChecks,
			},
		},
	})
}

func TestAccDataSourceOKEmptyProviderConfig(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {}

data "ssh2vsock_known_host" "testvm" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    port = 22
    username = "root"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
  guest = {
    cid = 113
    port = 22
  }
}`,
				ConfigStateChecks: knownHostDataSourceKnownValuesStateChecks,
			},
		},
	})
}

func TestAccDataSourceOKInheritProviderConfig(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    port = 22
    username = "root"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
}

data "ssh2vsock_known_host" "testvm" {
  guest = {
    cid = 113
    port = 22
  }
}`,
				ConfigStateChecks: knownHostDataSourceKnownValuesStateChecks,
			},
		},
	})
}

func TestAccDataSourceOKWithoutOptionalParams(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
}

data "ssh2vsock_known_host" "testvm" {
  guest = {
    cid = 113
  }
}`,
				ConfigStateChecks: knownHostDataSourceKnownValuesStateChecks,
			},
		},
	})
}

func TestAccDataSourceOKWithoutOptionalParamsNoProviderData(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {}

data "ssh2vsock_known_host" "testvm" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
  guest = {
    cid = 113
  }
}`,
				ConfigStateChecks: knownHostDataSourceKnownValuesStateChecks,
			},
		},
	})
}

func TestAccEphemeralResTunnelUnknownPort(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				Source: "hashicorp/null",
			},
			"random": {
				Source: "hashicorp/random",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {}

resource "random_integer" "port" {
  min = 22
  max = 22
}

ephemeral "ssh2vsock_tunnel" "tun" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
	port = random_integer.port.result
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
  guest = {
    cid = 113
	hostname = "vsock-113"
	username = "fmaury"
	password = "fmaury"
	ssh_ignore_host_key = true
  }
}

resource "null_resource" "use_ssh" {
  depends_on = [ephemeral.ssh2vsock_tunnel.tun]
  connection {
    host = "127.0.0.1"
	user = "fmaury"
	password = "fmaury"
	port = ephemeral.ssh2vsock_tunnel.tun.listen_port
	timeout = "10s"
  }
  provisioner "remote-exec" {
	inline = ["echo toto"]
  }
}`,
			},
		},
	})
}

func TestAccEphemeralResTunnelUnknownProviderPort(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				Source: "hashicorp/null",
			},
			"random": {
				Source: "hashicorp/random",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
	port = random_integer.port.result
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
}

resource "random_integer" "port" {
  min = 22
  max = 22
}

ephemeral "ssh2vsock_tunnel" "tun" {
  guest = {
    cid = 113
	hostname = "vsock-113"
	username = "fmaury"
	password = "fmaury"
	ssh_ignore_host_key = true
  }
}

resource "null_resource" "use_ssh" {
  depends_on = [ephemeral.ssh2vsock_tunnel.tun]
  connection {
    host = "127.0.0.1"
	user = "fmaury"
	password = "fmaury"
	port = ephemeral.ssh2vsock_tunnel.tun.listen_port
	timeout = "10s"
  }
  provisioner "remote-exec" {
	inline = ["echo toto"]
  }
}`,
			},
		},
	})
}

func TestAccEphemeralResTunnelOK(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				Source: "hashicorp/null",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
provider "ssh2vsock" {}

ephemeral "ssh2vsock_tunnel" "tun" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
    known_hosts = [
      "proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
  }
  guest = {
    cid = 113
	hostname = "vsock-113"
	username = "fmaury"
	password = "fmaury"
	ssh_ignore_host_key = true
  }
}

resource "null_resource" "use_ssh" {
  depends_on = [ephemeral.ssh2vsock_tunnel.tun]
  connection {
    host = "127.0.0.1"
	user = "fmaury"
	password = "fmaury"
	port = ephemeral.ssh2vsock_tunnel.tun.listen_port
	timeout = "10s"
  }
  provisioner "remote-exec" {
	inline = ["echo toto"]
  }
}`,
			},
		},
	})
}

func TestAccEphemeralResTunnelUseSSHFP(t *testing.T) {
	tmpdir := t.TempDir()
	caFile := path.Join(tmpdir, "ca.pem")

	f, err := os.OpenFile(caFile, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("failed to open cafile: %s", err.Error())
	}
	if _, err := io.WriteString(f, `-----BEGIN CERTIFICATE-----
MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkG
A1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jv
b3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAw
MDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9i
YWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxT
aWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZ
jc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavp
xy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp
1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdG
snUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJ
U26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N8
9iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8E
BTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0B
AQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOz
yj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE
38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymP
AbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUad
DKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbME
HMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A==
-----END CERTIFICATE-----`); err != nil {
		t.Fatalf("failed to write cafile content: %s", err.Error())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close file: %s", err.Error())
	}

	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"null": {
				Source: "hashicorp/null",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(`
provider "ssh2vsock" {}

ephemeral "ssh2vsock_tunnel" "tun" {
  hypervisor = {
    hostname = "proxmox.broken-by-design.fr"
    ssh_private_key = "/var/home/fmaury/.ssh/fma_ovh_rise2"
	use_sshfp = true
	dns_resolver = "8.8.8.8:853"
	ca_file = %q
  }
  guest = {
    cid = 113
	hostname = "vsock-113"
	username = "fmaury"
	password = "fmaury"
	ssh_ignore_host_key = true
  }
}

resource "null_resource" "use_ssh" {
  depends_on = [ephemeral.ssh2vsock_tunnel.tun]
  connection {
    host = "127.0.0.1"
	user = "fmaury"
	password = "fmaury"
	port = ephemeral.ssh2vsock_tunnel.tun.listen_port
	timeout = "10s"
  }
  provisioner "remote-exec" {
	inline = ["echo toto"]
  }
}`, caFile),
			},
		},
	})
}

var (
	_              statecheck.StateCheck = (*hashedSSHPubKeyStateChecker)(nil)
	ErrKeyNotFound                       = errors.New("key not found in output values")
)

type hashedSSHPubKeyStateChecker struct {
	parameterName    string
	expectedHostname string
	expectedKeyType  string
	expectedPubKey   string
}

func (f *hashedSSHPubKeyStateChecker) CheckState(ctx context.Context, req statecheck.CheckStateRequest, resp *statecheck.CheckStateResponse) {
	v, ok := req.State.Values.Outputs[f.parameterName]
	if !ok {
		resp.Error = ErrKeyNotFound
		return
	}
	strValue, ok := v.Value.(string)
	if !ok {
		resp.Error = fmt.Errorf("failed to cast %v to string", v.Value)
		return
	}

	parts := strings.Split(strValue, " ")
	if len(parts) != 3 {
		resp.Error = fmt.Errorf("unexpected number of parts in value: found %d", len(parts))
		return
	}
	if ok, err := ssh2vsock_types.CompareKnownHostWithHMAC(f.expectedHostname, parts[0]); err != nil {
		resp.Error = fmt.Errorf("failed to compare hostname: %s", err.Error())
		return
	} else if !ok {
		resp.Error = fmt.Errorf("unexpected hostname: %s", parts[0])
		return
	}

	if parts[1] != f.expectedKeyType {
		resp.Error = fmt.Errorf("unexpected key type: %s", parts[1])
		return
	}

	if parts[2] != f.expectedPubKey {
		resp.Error = fmt.Errorf("unexpected pubkey: %s", parts[2])
		return
	}
}

func TestKnownHostFunc(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"random": {
				Source: "hashicorp/random",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "random_id" "salt" {
  byte_length = 20
}
output "test_no_hash" {
  value = provider::ssh2vsock::make_known_host("AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8", "proxmox.broken-by-design.fr", 22, null)
}
output "test_hash" {
  value = provider::ssh2vsock::make_known_host("AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8", "proxmox.broken-by-design.fr", 22, random_id.salt.b64_std)
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("test_no_hash", knownvalue.StringExact(`proxmox.broken-by-design.fr ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8`)),
					&hashedSSHPubKeyStateChecker{
						parameterName:    "test_hash",
						expectedHostname: "proxmox.broken-by-design.fr",
						expectedKeyType:  ssh.KeyAlgoED25519,
						expectedPubKey:   "AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8",
					},
				},
			},
		},
	})
}

func TestKnownHostNonStandardPortFunc(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		ExternalProviders: map[string]resource.ExternalProvider{
			"random": {
				Source: "hashicorp/random",
			},
		},
		Steps: []resource.TestStep{
			{
				Config: `
resource "random_id" "salt" {
  byte_length = 20
}
output "test_no_hash" {
  value = provider::ssh2vsock::make_known_host("AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8", "proxmox.broken-by-design.fr", 2222, null)
}
output "test_hash" {
  value = provider::ssh2vsock::make_known_host("AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8", "proxmox.broken-by-design.fr", 2222, random_id.salt.b64_std)
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("test_no_hash", knownvalue.StringExact(`[proxmox.broken-by-design.fr]:2222 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8`)),
					&hashedSSHPubKeyStateChecker{
						parameterName:    "test_hash",
						expectedHostname: "[proxmox.broken-by-design.fr]:2222",
						expectedKeyType:  ssh.KeyAlgoED25519,
						expectedPubKey:   "AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8",
					},
				},
			},
		},
	})
}

func TestSSHFPFunc(t *testing.T) {
	resource.Test(t, resource.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"ssh2vsock": providerserver.NewProtocol6WithError(provider.New(version)()),
		},
		Steps: []resource.TestStep{
			{
				Config: `
locals {
  sshfp = provider::ssh2vsock::make_sshfp("AAAAC3NzaC1lZDI1NTE5AAAAINZbOgyyTUFPwyyFVPmClwzi7NPfg3N/Dp4Ojs3c8cCU")
}

output "algorithm" {
  value = local.sshfp.algorithm
}
output "type" {
  value = local.sshfp.type
}
output "fingerprint" {
  value = local.sshfp.fingerprint
}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownOutputValue("algorithm", knownvalue.Int32Exact(4)),
					statecheck.ExpectKnownOutputValue("type", knownvalue.Int32Exact(2)),
					statecheck.ExpectKnownOutputValue("fingerprint", knownvalue.StringExact("bb15cf9c7da36457476e529b72ff7ee86ab657ed21a7dbc3c32473ebe20ad132")),
				},
			},
		},
	})
}
