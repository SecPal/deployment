# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

# Canonical provider-bound representation. The workflow and credential-free tests
# evaluate these exact locals with pinned OpenTofu; no second renderer owns it.
locals {
  rocky_bootstrap_sources = {
    postgresql_candidate                = var.postgresql_candidate_json
    postgresql_consumer                 = file("${path.module}/../../../scripts/render-native-postgresql.py")
    postgresql_contract                 = file("${path.module}/../../../scripts/ci-cloud/postgresql_qualification_contract.py")
    postgresql_control                  = file("${path.module}/../../../scripts/ci-cloud/postgresql-qualification-control.py")
    postgresql_runner                   = file("${path.module}/../../../scripts/ci-cloud/qualify-native-postgresql.py")
    postgresql_application_bootstrap    = file("${path.module}/../../../scripts/ci-cloud/postgresql-application-bootstrap.php")
    postgresql_application_probe        = file("${path.module}/../../../scripts/ci-cloud/postgresql-application-probe.php")
    image_attestation_runtime           = file("${path.module}/../../../scripts/image_attestation_runtime.py")
    fetch_oci_attestation               = file("${path.module}/../../../scripts/fetch-oci-attestation.py")
    postgresql_wrapper                  = file("${path.module}/../../../scripts/ci-cloud/run-native-postgresql-qualification.sh")
    postgresql_diagnostic_schema        = file("${path.module}/../../../schemas/postgresql-qualification-diagnostic.schema.json")
    postgresql_schema                   = file("${path.module}/../../../schemas/postgresql-qualification-evidence.schema.json")
    integration_runtime_contract        = file("${path.module}/../../../scripts/integration_runtime_contract.py")
    prepare_script                      = file("${path.module}/../../../scripts/ci-cloud/prepare-rocky-host.sh")
    readiness_publisher                 = file("${path.module}/../../../scripts/ci-cloud/publish-rocky-qualification-readiness.py")
    runtime_user_systemd                = file("${path.module}/../../../scripts/ci-cloud/runtime_user_systemd.py")
    target_runner                       = file("${path.module}/../../../scripts/ci-cloud/run-rocky-target-qualification.sh")
    target_failure_classifier           = file("${path.module}/../../../scripts/ci-cloud/classify-rocky-target-qualification-failure.py")
    target_replay_verifier              = file("${path.module}/../../../scripts/ci-cloud/verify-rocky-target-qualification-replay.py")
    target_trace                        = file("${path.module}/../../../scripts/ci-cloud/rocky-target-qualification-trace.sh")
    reload_runuser                      = file("${path.module}/../../../scripts/ci-cloud/rocky-reload-runuser.py")
    reload_systemctl                    = file("${path.module}/../../../scripts/ci-cloud/rocky-reload-systemctl.py")
    start_runuser                       = file("${path.module}/../../../scripts/ci-cloud/rocky-start-runuser.py")
    start_env                           = file("${path.module}/../../../scripts/ci-cloud/rocky-start-env.py")
    start_systemctl                     = file("${path.module}/../../../scripts/ci-cloud/rocky-start-systemctl.py")
    active_runuser                      = file("${path.module}/../../../scripts/ci-cloud/rocky-active-runuser.py")
    active_env                          = file("${path.module}/../../../scripts/ci-cloud/rocky-active-env.py")
    active_systemctl                    = file("${path.module}/../../../scripts/ci-cloud/rocky-active-systemctl.py")
    primary_runuser                     = file("${path.module}/../../../scripts/ci-cloud/rocky-primary-runuser.py")
    primary_runtime                     = file("${path.module}/../../../scripts/ci-cloud/rocky-primary-runtime.py")
    reload_observer                     = file("${path.module}/../../../scripts/ci-cloud/observe-rocky-quadlet-reload-adjacency.py")
    allocator                           = file("${path.module}/../../../scripts/ci-cloud/allocate-rocky-subids.py")
    collector                           = file("${path.module}/../../../scripts/ci-cloud/collect-rocky-preparation.py")
    preparation_contract                = file("${path.module}/../../../scripts/ci-cloud/rocky_preparation_contract.py")
    control_utility                     = file("${path.module}/../../../scripts/ci-cloud/rocky-control.py")
    selinux_isolation_contract          = file("${path.module}/../../../scripts/selinux_isolation_contract.py")
    quadlet_authority_contract          = file("${path.module}/../../../scripts/quadlet_authority_contract.py")
    discovery_schema                    = file("${path.module}/../../../schemas/rocky-cloud-discovery-evidence.schema.json")
    continuation_schema                 = file("${path.module}/../../../schemas/rocky-cloud-continuation.schema.json")
    preparation_schema                  = file("${path.module}/../../../schemas/rocky-cloud-preparation-evidence.schema.json")
    preparation_failure_schema          = file("${path.module}/../../../schemas/rocky-cloud-preparation-failure-evidence.schema.json")
    qualification_schema                = file("${path.module}/../../../schemas/rocky-cloud-qualification-evidence.schema.json")
    target_source_failure_schema        = file("${path.module}/../../../schemas/rocky-cloud-target-source-failure.schema.json")
    target_qualification_failure_schema = file("${path.module}/../../../schemas/rocky-cloud-target-qualification-failure.schema.json")
    arm64_profile                       = file("${path.module}/../../../config/ci-cloud/gcp-rocky-10-2-arm64.json")
    x86_64_profile                      = file("${path.module}/../../../config/ci-cloud/gcp-rocky-10-2-x86-64.json")
  }
  rocky_bootstrap_payload = jsonencode(local.rocky_bootstrap_sources)
  rocky_startup = templatefile("${path.module}/../../../scripts/ci-cloud/bootstrap-rocky-host.tftpl", {
    payload_base64gzip     = base64gzip(local.rocky_bootstrap_payload)
    payload_sha256         = sha256(local.rocky_bootstrap_payload)
    payload_bytes          = length(base64encode(local.rocky_bootstrap_payload)) * 3 / 4 - length(regexall("=", base64encode(local.rocky_bootstrap_payload)))
    component_names_base64 = base64encode(jsonencode(sort(keys(local.rocky_bootstrap_sources))))
  })
  rocky_metadata = {
    block-project-ssh-keys               = "true"
    disable-legacy-endpoints             = "true"
    enable-oslogin                       = "FALSE"
    secpal-rocky-cloud-identity-admitted = "false"
    secpal-rocky-qualification-request   = "prepare"
    secpal-rocky-target-sha              = var.target_sha
    secpal-rocky-trusted-control-sha     = var.trusted_control_sha
    secpal-rocky-exact-image-self-link   = var.exact_image_self_link
    secpal-rocky-provider-profile        = var.profile
    secpal-rocky-expires-at              = var.expires_at
    secpal-rocky-ssh-public-key          = trimspace(var.ssh_public_key)
    "startup-script"                     = local.rocky_startup

  }

  # GCP: keys <= 128 bytes, values <= 256 KiB, key+value total <= 512 KiB.
  # Reserve 24 KiB: one 16 KiB maximum candidate-sized growth allowance after
  # worst-case gzip/base64 expansion (ceil(16384/3)*4 plus gzip overhead),
  # rounded up to the next 8 KiB. This also covers bounded transition metadata.
  rocky_metadata_headroom               = 24 * 1024
  rocky_metadata_value_limit            = 256 * 1024
  rocky_metadata_aggregate_limit        = 512 * 1024
  rocky_metadata_value_safe_maximum     = local.rocky_metadata_value_limit - local.rocky_metadata_headroom
  rocky_metadata_aggregate_safe_maximum = local.rocky_metadata_aggregate_limit - local.rocky_metadata_headroom
  # base64 length yields UTF-8 bytes, rather than Unicode character count.
  # Declassify only bounded sizes; payload/source bodies stay suppressed.
  rocky_metadata_sizes = nonsensitive({ for key, value in local.rocky_metadata : key => {
    key_bytes   = nonsensitive(length(base64encode(key)) * 3 / 4 - length(regexall("=", base64encode(key))))
    value_bytes = nonsensitive(length(base64encode(value)) * 3 / 4 - length(regexall("=", base64encode(value))))
  } })
  rocky_metadata_aggregate_bytes     = sum([for size in values(local.rocky_metadata_sizes) : size.key_bytes + size.value_bytes])
  rocky_metadata_values_admitted     = alltrue([for size in values(local.rocky_metadata_sizes) : size.key_bytes <= 128 && size.value_bytes <= local.rocky_metadata_value_safe_maximum])
  rocky_metadata_aggregate_admitted  = local.rocky_metadata_aggregate_bytes <= local.rocky_metadata_aggregate_safe_maximum
  rocky_bootstrap_expansion_admitted = local.rocky_metadata_decoded_bytes <= 1024 * 1024
  rocky_metadata_decoded_bytes       = nonsensitive(length(base64encode(local.rocky_bootstrap_payload)) * 3 / 4 - length(regexall("=", base64encode(local.rocky_bootstrap_payload))))
  rocky_metadata_admission = {
    admitted               = local.rocky_metadata_values_admitted && local.rocky_metadata_aggregate_admitted && local.rocky_bootstrap_expansion_admitted
    values                 = local.rocky_metadata_sizes
    value_limit            = local.rocky_metadata_value_limit
    value_safe_maximum     = local.rocky_metadata_value_safe_maximum
    key_limit              = 128
    aggregate_bytes        = local.rocky_metadata_aggregate_bytes
    aggregate_limit        = local.rocky_metadata_aggregate_limit
    aggregate_safe_maximum = local.rocky_metadata_aggregate_safe_maximum
    decoded_bytes          = local.rocky_metadata_decoded_bytes
    decoded_limit          = 1024 * 1024
  }
}

# This guard is a prerequisite of every resource root, including when the
# workflow's credential-free admission is bypassed. A failing plan creates none.
resource "terraform_data" "rocky_metadata_admission" {
  lifecycle {
    precondition {
      condition     = local.rocky_metadata_values_admitted
      error_message = "ROCKY_METADATA_VALUE_TOO_LARGE safe_maximum=${local.rocky_metadata_value_safe_maximum} provider_maximum=${local.rocky_metadata_value_limit} sizes=${jsonencode(local.rocky_metadata_sizes)}"
    }
    precondition {
      condition     = local.rocky_metadata_aggregate_admitted
      error_message = "ROCKY_METADATA_AGGREGATE_TOO_LARGE actual=${local.rocky_metadata_aggregate_bytes} safe_maximum=${local.rocky_metadata_aggregate_safe_maximum} provider_maximum=${local.rocky_metadata_aggregate_limit}"
    }
    precondition {
      condition     = local.rocky_bootstrap_expansion_admitted
      error_message = "ROCKY_BOOTSTRAP_EXPANSION_TOO_LARGE actual=${local.rocky_metadata_admission.decoded_bytes} maximum=${local.rocky_metadata_admission.decoded_limit}"
    }
  }
}
