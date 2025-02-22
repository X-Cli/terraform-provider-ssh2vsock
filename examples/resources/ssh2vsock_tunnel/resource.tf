# With all hypervisor options specified at the provider level
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

# This example connects to the hypervisor "proxmox.example.com" on port 22. It authenticates to the user "example" with a public key from a SSH agent whose socket is specified by the SSH_AUTH_SOCK environment variable.
# The host key of the SSH server of the hypervisor is checked using the DNS, and a local DNSSEC resolver/validator.
# The tunnel is then established with a guest virtual machine whose address is the CID 3 and whose SSH service listens on an AF_VSOCK socket on port 22. The authentication is done on the "example" account, using the same SSH agent than for the hypervisor.
ephemeral "ssh2vsock_tunnel" "example_vm" {
  guest = {
    cid                 = 3
    ssh_ignore_host_key = true
  }
}

# This resource uses the tunnel established by the ssh2vsock_tunnel ephemeral resource and "touches" a "/tmp/toto" on the guest vitual machine
resource "null_resource" "use_ssh" {
  depends_on = [ephemeral.ssh2vsock_tunnel.tun]
  connection {
    host    = "127.0.0.1"
    user    = "example"
    agent   = true
    port    = ephemeral.ssh2vsock_tunnel.tun.listen_port
    timeout = "10s"
  }
  provisioner "remote-exec" {
    inline = ["touch /tmp/toto"]
  }
}
