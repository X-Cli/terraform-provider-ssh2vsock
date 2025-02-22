# Using no option (all values are defined at the resource/data source level)
provider "ssh2vsock" {}

# Using mostly the default values, an SSH agent for authentication and SSHFP for host key verification
provider "ssh2vsock" {
  hypervisor = {
    hostname      = "proxmox.example.com"
    ssh_use_agent = true
    use_sshfp     = true
    dns_resolver  = "127.0.0.1:53"
  }
}

# Using password for authentication and the user known_hosts file
provider "ssh2vsock" {
  hypervisor = {
    hostname        = "libvirt.example.com"
    password        = "rootpassword"
    known_host_file = "/home/fmaury/.ssh/known_hosts"
  }
}

# Using a bit of all options
provider "ssh2vsock" {
  hypervisor = {
    hostname                   = "proxmox.example.com"
    port                       = 2222
    username                   = "administrator"
    ssh_private_key            = "/home/fmaury/.ssh/example_key"
    ssh_private_key_passphrase = "mysecret"
    known_host = [
      "proxmox.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDGBwap8CS/9zniYhI/Hh/6jq7SG2ysFU43WHvpP41rz",
    ]
    known_host_file = "/home/fmaury/.ssh/known_hosts"
    use_sshfp       = true
    dns_resolver    = "dns.google:853"
    ca_file         = "/etc/ssl/certs/ca-certificates.crt"
  }
}
