# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

locals {
  run_suffix = "${var.run_id}-${var.run_attempt}"
  labels = {
    secpal_ci_owner    = "rocky-host-qualification"
    repository         = "secpal-deployment"
    github_run_id      = var.run_id
    github_run_attempt = var.run_attempt
    target_sha         = var.target_sha
    control_sha        = var.trusted_control_sha
    provider_profile   = var.profile
    created_at         = var.created_at
    expires_at         = var.expires_at
  }
  description_ownership = {
    o = "rocky-host-qualification"
    r = "secpal-deployment"
    i = var.run_id
    a = var.run_attempt
    t = var.target_sha
    c = var.trusted_control_sha
    p = var.profile
    n = var.created_at
    x = var.expires_at
  }
  ownership_description = jsonencode(local.description_ownership)
  network_tag           = "sprk-${local.run_suffix}"
}

resource "google_compute_network" "qualification" {
  name                    = "sprk-${local.run_suffix}-network"
  description             = local.ownership_description
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

resource "google_compute_subnetwork" "qualification" {
  name                     = "sprk-${local.run_suffix}-subnet"
  description              = local.ownership_description
  ip_cidr_range            = "10.82.0.0/24"
  region                   = "europe-west3"
  network                  = google_compute_network.qualification.id
  private_ip_google_access = false
  stack_type               = "IPV4_ONLY"
}

resource "google_compute_firewall" "ssh" {
  name          = "sprk-${local.run_suffix}-ssh"
  description   = local.ownership_description
  network       = google_compute_network.qualification.id
  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["${var.runner_ipv4}/32"]
  target_tags   = [local.network_tag]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "egress_allow" {
  name               = "sprk-${local.run_suffix}-egress-allow"
  description        = local.ownership_description
  network            = google_compute_network.qualification.id
  direction          = "EGRESS"
  priority           = 1000
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
  name               = "sprk-${local.run_suffix}-egress-deny"
  description        = local.ownership_description
  network            = google_compute_network.qualification.id
  direction          = "EGRESS"
  priority           = 65534
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = [local.network_tag]

  deny {
    protocol = "all"
  }
}

resource "google_compute_disk" "qualification" {
  name   = "sprk-${local.run_suffix}-disk"
  zone   = var.zone
  type   = var.disk_type
  size   = var.disk_size_gib
  image  = var.exact_image_self_link
  labels = local.labels
}

resource "google_compute_instance" "qualification" {
  name         = "sprk-${local.run_suffix}-instance"
  description  = local.ownership_description
  zone         = var.zone
  machine_type = var.machine_type

  can_ip_forward      = false
  deletion_protection = false
  enable_display      = false
  labels              = local.labels
  tags                = [local.network_tag]

  boot_disk {
    source      = google_compute_disk.qualification.self_link
    auto_delete = false
  }

  network_interface {
    subnetwork = google_compute_subnetwork.qualification.id
    stack_type = "IPV4_ONLY"
    nic_type   = "GVNIC"
    access_config {
      network_tier = "STANDARD"
    }
  }

  service_account {
    email  = var.bootstrap_service_account
    scopes = []
  }

  metadata = {
    block-project-ssh-keys               = "true"
    disable-legacy-endpoints             = "true"
    enable-oslogin                       = "FALSE"
    secpal-rocky-cloud-identity-admitted = "false"
    secpal-rocky-qualification-request   = "prepare"
    secpal-rocky-target-sha              = var.target_sha
    secpal-rocky-trusted-control-sha     = var.trusted_control_sha
    secpal-rocky-exact-image-self-link   = var.exact_image_self_link
    secpal-rocky-expires-at              = var.expires_at
    secpal-rocky-ssh-public-key          = trimspace(var.ssh_public_key)
    "startup-script" = templatefile("${path.module}/../../../scripts/ci-cloud/bootstrap-rocky-host.tftpl", {
      prepare_script_base64gzip                      = base64gzip(file("${path.module}/../../../scripts/ci-cloud/prepare-rocky-host.sh"))
      readiness_publisher_base64gzip                 = base64gzip(file("${path.module}/../../../scripts/ci-cloud/publish-rocky-qualification-readiness.py"))
      target_runner_base64gzip                       = base64gzip(file("${path.module}/../../../scripts/ci-cloud/run-rocky-target-qualification.sh"))
      target_failure_classifier_base64gzip           = base64gzip(file("${path.module}/../../../scripts/ci-cloud/classify-rocky-target-qualification-failure.py"))
      target_trace_base64gzip                        = base64gzip(file("${path.module}/../../../scripts/ci-cloud/rocky-target-qualification-trace.sh"))
      reload_observer_base64gzip                     = base64gzip(file("${path.module}/../../../scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py"))
      allocator_base64gzip                           = base64gzip(file("${path.module}/../../../scripts/ci-cloud/allocate-rocky-subids.py"))
      collector_base64gzip                           = base64gzip(file("${path.module}/../../../scripts/ci-cloud/collect-rocky-preparation.py"))
      preparation_contract_base64gzip                = base64gzip(file("${path.module}/../../../scripts/ci-cloud/rocky_preparation_contract.py"))
      control_utility_base64gzip                     = base64gzip(file("${path.module}/../../../scripts/ci-cloud/rocky-control.py"))
      discovery_schema_base64gzip                    = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-discovery-evidence.schema.json"))
      continuation_schema_base64gzip                 = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-continuation.schema.json"))
      preparation_schema_base64gzip                  = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-preparation-evidence.schema.json"))
      preparation_failure_schema_base64gzip          = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-preparation-failure-evidence.schema.json"))
      qualification_schema_base64gzip                = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-qualification-evidence.schema.json"))
      target_source_failure_schema_base64gzip        = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-target-source-failure.schema.json"))
      target_qualification_failure_schema_base64gzip = base64gzip(file("${path.module}/../../../schemas/rocky-cloud-target-qualification-failure.schema.json"))
      profile_base64gzip                             = base64gzip(file("${path.module}/../../../config/ci-cloud/gcp-rocky-10-2-arm64.json"))
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
