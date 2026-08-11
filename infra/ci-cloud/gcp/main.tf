# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

locals {
  run_suffix = "${var.run_id}-${var.run_attempt}"
  labels = {
    secpal_ci_owner    = "deployment-conformance"
    repository         = "secpal-deployment"
    github_run_id      = var.run_id
    github_run_attempt = var.run_attempt
    target_sha         = var.target_sha
    created_at         = var.created_at
    expires_at         = var.expires_at
  }
  network_tag = "spci-${local.run_suffix}"
}

data "google_compute_image" "debian_13" {
  family  = "debian-13-arm64"
  project = "debian-cloud"
}

resource "google_compute_network" "conformance" {
  name                    = "spci-${local.run_suffix}-network"
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "conformance" {
  name                     = "spci-${local.run_suffix}-subnet"
  ip_cidr_range            = "10.13.0.0/24"
  region                   = "europe-west3"
  network                  = google_compute_network.conformance.id
  private_ip_google_access = false
  stack_type               = "IPV4_ONLY"
}

resource "google_compute_firewall" "ssh" {
  name      = "spci-${local.run_suffix}-ssh"
  network   = google_compute_network.conformance.id
  direction = "INGRESS"
  priority  = 1000

  source_ranges = ["${var.runner_ipv4}/32"]
  target_tags   = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "egress_allow" {
  name      = "spci-${local.run_suffix}-egress-allow"
  network   = google_compute_network.conformance.id
  direction = "EGRESS"
  priority  = 1000

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["53", "80", "443"]
  }

  allow {
    protocol = "udp"
    ports    = ["53", "123"]
  }
}

resource "google_compute_firewall" "egress_deny" {
  name      = "spci-${local.run_suffix}-egress-deny"
  network   = google_compute_network.conformance.id
  direction = "EGRESS"
  priority  = 65534

  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.network_tag]

  deny {
    protocol = "all"
  }
}

resource "google_compute_disk" "conformance" {
  name   = "spci-${local.run_suffix}-disk"
  zone   = var.zone
  type   = "hyperdisk-balanced"
  size   = 120
  image  = data.google_compute_image.debian_13.self_link
  labels = local.labels
}

resource "google_compute_instance" "conformance" {
  name         = "spci-${local.run_suffix}-instance"
  zone         = var.zone
  machine_type = "c4a-standard-4"

  can_ip_forward      = false
  deletion_protection = false
  enable_display      = false
  labels              = local.labels
  tags                = [local.network_tag]

  boot_disk {
    source      = google_compute_disk.conformance.self_link
    auto_delete = false
  }

  network_interface {
    subnetwork = google_compute_subnetwork.conformance.id
    stack_type = "IPV4_ONLY"
    nic_type   = "GVNIC"

    access_config {
      network_tier = "STANDARD"
    }
  }

  metadata = {
    block-project-ssh-keys   = "true"
    disable-legacy-endpoints = "true"
    enable-oslogin           = "FALSE"
    user-data = templatefile("${path.module}/cloud-init.tftpl", {
      ssh_public_key            = trimspace(var.ssh_public_key)
      host_setup_script         = indent(6, trimspace(file("${path.module}/../../../scripts/ci-cloud/configure-conformance-host.sh")))
      host_setup_failure_script = indent(6, trimspace(file("${path.module}/../../../scripts/ci-cloud/host-setup-failure.py")))
    })
  }

  scheduling {
    automatic_restart   = false
    on_host_maintenance = "TERMINATE"
    preemptible         = false
    provisioning_model  = "STANDARD"
  }

  shielded_instance_config {
    enable_integrity_monitoring = true
    enable_secure_boot          = true
    enable_vtpm                 = true
  }

  depends_on = [
    google_compute_firewall.ssh,
    google_compute_firewall.egress_allow,
    google_compute_firewall.egress_deny,
  ]
}
