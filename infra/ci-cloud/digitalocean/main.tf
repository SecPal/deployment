# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

locals {
  run_suffix    = "${var.run_id}-${var.run_attempt}"
  resource_name = "spci-${local.run_suffix}"
  size_by_cpu = {
    intel = "s-8vcpu-16gb-intel"
    amd   = "s-8vcpu-16gb-amd"
  }

  owner_tag   = "spci-owner-${local.run_suffix}"
  repo_tag    = "spci-repo-secpal-deployment-${local.run_suffix}"
  sha_tag     = "spci-sha-${var.target_sha}-${local.run_suffix}"
  created_tag = "spci-created-${var.created_at}-${local.run_suffix}"
  expires_tag = "spci-expires-${var.expires_at}-${local.run_suffix}"

  ownership_tags = [
    local.owner_tag,
    local.repo_tag,
    local.sha_tag,
    local.created_tag,
    local.expires_tag,
  ]
}

data "digitalocean_image" "debian_13" {
  slug = "debian-13-x64"
}

resource "digitalocean_tag" "ownership" {
  for_each = toset(local.ownership_tags)
  name     = each.value
}

resource "digitalocean_ssh_key" "ephemeral" {
  name       = local.resource_name
  public_key = trimspace(var.ssh_public_key)
}

resource "digitalocean_droplet" "conformance" {
  name              = local.resource_name
  image             = data.digitalocean_image.debian_13.id
  region            = var.region
  size              = local.size_by_cpu[var.cpu_profile]
  backups           = false
  monitoring        = false
  ipv6              = false
  droplet_agent     = false
  graceful_shutdown = false
  ssh_keys          = [digitalocean_ssh_key.ephemeral.fingerprint]
  tags              = [for tag in digitalocean_tag.ownership : tag.name]
  depends_on        = [digitalocean_firewall.conformance]
  user_data = templatefile("${path.module}/cloud-init.tftpl", {
    ssh_public_key    = trimspace(var.ssh_public_key)
    host_setup_script = indent(6, trimspace(file("${path.module}/../../../scripts/ci-cloud/configure-conformance-host.sh")))
  })
}

resource "digitalocean_firewall" "conformance" {
  name = local.resource_name
  tags = [digitalocean_tag.ownership[local.owner_tag].name]

  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["${var.runner_ipv4}/32"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "53"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "80"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "tcp"
    port_range            = "443"
    destination_addresses = ["0.0.0.0/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "123"
    destination_addresses = ["0.0.0.0/0"]
  }
}
