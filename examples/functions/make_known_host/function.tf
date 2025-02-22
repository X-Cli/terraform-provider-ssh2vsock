locals {
  public_key = "AAAAC3NzaC1lZDI1NTE5AAAAIJz12DGyEg2G8BylpI/02ZSgLMj+yGq7rXB/lRGjuzL8"
}
resource "random_id" "salt" {
  byte_length = 20
}

output "known_host_entry_nohash" {
  value = provider::ssh2vsock::make_known_host(local.public_key, "example.com", null)
}

output "known_host_entry_with_hashed_hostname" {
  value = provider::ssh2vsock::make_known_host(local.public_key, "example.com", random_id.salt.b64_std)
}