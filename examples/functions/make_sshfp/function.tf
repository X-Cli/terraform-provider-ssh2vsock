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
