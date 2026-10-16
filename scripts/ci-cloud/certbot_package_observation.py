#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Native Certbot schema boundary; consumes the Rocky provenance owner."""

import re
from pathlib import Path
from typing import Any
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
import rocky_preparation_contract as host_provenance


def validate(path: Path, target_sha: str, root: Path, error_type: type[Exception], load_object) -> dict[str, Any]:
    """Semantic admission only; native transport must authenticate the producer.

    This consumes #308's host owner, and cannot replace the separate trusted
    Rocky host qualification or treat arbitrary local JSON as native evidence.
    """
    if re.fullmatch(r"[0-9a-f]{40}", target_sha) is None:
        raise error_type("Certbot observation target binding is invalid")
    schema = load_object(root / "schemas/certbot-package-observation.schema.json")
    host_schema = load_object(root / "schemas/production-host-facts.schema.json")
    registry = Registry().with_resource(host_schema["$id"], Resource.from_contents(host_schema))
    observation = load_object(path)
    if list(Draft202012Validator(schema, registry=registry).iter_errors(observation)):
        raise error_type("Certbot observation closed schema rejected")
    if observation["target_sha"] != target_sha:
        raise error_type("Certbot observation is bound to another target")
    policy = load_object(root / "config/production/certbot-package-policy.json")
    try:
        admitted = host_provenance.admit_certbot_exception(
            observation["package_provenance"], observation["architecture"], policy
        )
    except host_provenance.ContractError as error:
        raise error_type("TLS-specific Certbot package provenance rejected") from error
    if admitted is None:
        raise error_type("Certbot native observation requires the exact exception")
    return observation
