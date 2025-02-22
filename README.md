# SSH2VSock Terraform Provider

The ssh2vsock provider enables practitioners to reach virtual machines over SSH
via their hypervisor using [AF_VSOCK
sockets](https://www.man7.org/linux/man-pages/man7/vsock.7.html).

As opposed to most SSH-related Terraform providers, this one goes a long way in
order to secure the SSH connections, by verifying the host keys using a list of
known host entries, a classic known host file or
[SSHFP](https://www.rfc-editor.org/rfc/rfc4255) records. It is compatible with
both hashed and non-hashed known host entries.

The ssh2vsock provider enables practitioners to reach virtual machines over SSH
via their hypervisor using AF_VSOCK sockets.

As opposed to most SSH-related Terraform providers, this one goes a long way in
order to secure the SSH connections by verifying the host keys using a list of
known host entries, a classic known host file or SSHFP records. It is compatible
with both hashed and non-hashed known host entries.

This provider can also be used to secure SSH connections of other insecure SSH
connections by tunneling their insecure communications over a secure series of
tunnels.

It also provides utility functions to generate known host entries and structured
SSHFP records to insert into the DNS.

SSHFP fingerprints must be signed with DNSSEC and verified (AD bit set) to be
trusted, and the provider offers optional support of DNS-over-TLS with
certificate verification to transport the result of the DNSSEC signature
verification.

This provider only negotiates host key algorithms for which it has a known host
entry or a SSHFP fingerprint. That is to say that if the only known host entry
configured uses ssh-ed25519, then only ssh-ed25519 will be proposed during the
handshake as an acceptable host key algorithm. If you get an error about a
handshake failure because of the lack of common host key algorithms, please
consider adding some known host entries with an algorithm that is currently
accepted by the server.

This provider requires the guest VMs SSH service to listen on the AF_VSOCK
address family. This is generally achieved thanks to systemd socket activation
and systemd ssh configuration generator that automatically detects the virtual
machine environment.

This provider also requires that the VM is configured with a AF_VSOCK context
ID. With KVM, this is generally done by adding an argument, such as "-device
vhost-vsock-pci,guest-cid=3". See QEMU documentation for more information.

Finally, this provider requires that socat binary is installed on the
hypervisor.

More documentation can be found in the docs/ directory of this repository
