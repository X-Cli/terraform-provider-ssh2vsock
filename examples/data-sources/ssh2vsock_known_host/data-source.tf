# Example with all hypervisor options specified at the provider level
# provider "ssh2vsock" {
#     hypervisor = {
#         hostname = "proxmox.example.com"
#         port = 22
#         username = "example"
#         ssh_use_agent = true
#         use_sshfp = true
#         dns_resolver = "127.0.0.1:53"
#     }
# }

data "ssh2vsock_known_host" "example_vm" {
  guest = {
    cid = 3
  }
}

output "rsa_public_key" {
  value = data.ssh2vsock_known_host.example_vm.rsa_public_key
}

output "ecdsa_public_key" {
  value = data.ssh2vsock_known_host.example_vm.ecdsa_public_key
}

output "ed25519_public_key" {
  value = data.ssh2vsock_known_host.example_vm.ed25519_public_key
}

# Another example with data source level connection info to the hypervisor
data "ssh2vsock_known_host" "example_vm" {
  hypervisor = {
    hostname        = "proxmox.example.com"
    ssh_use_agent   = true
    known_host_file = "/home/fmaury/.ssh/known_hosts"
  }
  guest = {
    cid = 3
  }
}
