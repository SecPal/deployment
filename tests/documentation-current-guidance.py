#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Bounded classification contract for deployment documentation authority."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ADR_019 = (
    "https://github.com/SecPal/.github/blob/main/docs/adr/"
    "20260824-production-edge-layered-security-adr019.md"
)


class Authority(Enum):
    CURRENT_GUIDANCE = "current-guidance"
    CURRENT_TECHNICAL = "current-technical"
    IN_PROGRESS_TECHNICAL = "in-progress-technical"
    HISTORICAL_RECORD = "historical-record"
    IMMUTABLE_HISTORY = "immutable-history"


DOCUMENT_AUTHORITY = {
    Path("AGENTS.md"): Authority.CURRENT_GUIDANCE,
    Path(".github/copilot-instructions.md"): Authority.CURRENT_GUIDANCE,
    Path("README.md"): Authority.CURRENT_GUIDANCE,
    Path("docs/roadmap.md"): Authority.CURRENT_GUIDANCE,
    Path("docs/architecture/scope.md"): Authority.CURRENT_GUIDANCE,
    Path("docs/quadlet-integration.md"): Authority.CURRENT_TECHNICAL,
    Path("docs/api-image-consumption.md"): Authority.CURRENT_TECHNICAL,
    Path("docs/frontend-image-consumption.md"): Authority.CURRENT_TECHNICAL,
    Path("docs/rocky-cloud-qualification.md"): Authority.IN_PROGRESS_TECHNICAL,
    Path("docs/ci-cloud-conformance.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-host.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-inventory.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-secrets.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/production-state.md"): Authority.HISTORICAL_RECORD,
    Path("docs/architecture/decisions/production-edge.md"): Authority.HISTORICAL_RECORD,
    Path("CHANGELOG.md"): Authority.IMMUTABLE_HISTORY,
}

OBSOLETE_CURRENT_SUPPORT = {
    "Compose execution": re.compile(r"\b(?:run|start|deploy with)\s+docker compose\b", re.I),
    "Valkey startup": re.compile(r"\b(?:run|start|deploy)\s+Valkey\b", re.I),
    "Debian current admission": re.compile(
        r"\bSchema version 1 admits only Debian 13/trixie hosts\b", re.I
    ),
    "Debian current conformance heading": re.compile(
        r"^#{2,3} (?:Ephemeral|Independent) Debian 13 cloud conformance", re.I | re.M
    ),
    "old edge decision": re.compile(r"\bD\.3 selects a pinned Debian NGINX\b", re.I),
    "old build vocabulary": re.compile(r"\b(?:Product|Their) Dockerfiles\b"),
    "edge-only CrowdSec": re.compile(r"\bCrowdSec belongs at the public edge\b", re.I),
    "Valkey future topology": re.compile(
        r"\bValkey never replaces PostgreSQL as the source of truth\b", re.I
    ),
    "Caddy production edge": re.compile(
        r"\b(?:"
        r"Caddy\s+(?:is|serves\s+as)\s+(?:the\s+)?(?:current\s+)?"
        r"production(?:\s+public)?\s+(?:edge|gateway)"
        r"|production(?:\s+current)?\s+(?:traffic|requests?)\s+(?:is|are)\s+"
        r"(?:terminated|routed|handled)\s+by\s+Caddy"
        r"|Caddy\s+(?:terminates|routes|handles)\s+(?:current\s+)?"
        r"production\s+(?:traffic|requests?)"
        r")\b",
        re.I,
    ),
    "old implementation status": re.compile(
        r"\bD\.1 host contract,\s+D\.1a integration-runtime parity, and D\.2"
        r"[^.]{0,100}\bare implemented\b",
        re.I | re.S,
    ),
}

TOKEN_CANONICAL = {
    "#89": "issue89",
    "backed": "back",
    "backs": "back",
    "defined": "define",
    "defines": "define",
    "deployments": "deployment",
    "enters": "enter",
    "exposes": "expose",
    "handled": "handle",
    "handles": "handle",
    "hosts": "host",
    "installations": "installation",
    "modes": "mode",
    "needed": "need",
    "needs": "need",
    "owns": "own",
    "postgresql": "postgres",
    "provided": "provide",
    "provides": "provide",
    "queues": "queue",
    "required": "require",
    "requires": "require",
    "routed": "route",
    "routes": "route",
    "runs": "run",
    "served": "serve",
    "serves": "serve",
    "sessions": "session",
    "stores": "store",
    "supported": "support",
    "terminated": "terminate",
    "terminates": "terminate",
    "used": "use",
    "uses": "use",
}

NEGATION_TOKENS = {"no", "not", "never", "neither", "without"}
NON_CURRENT_ASSERTION_TOKENS = {
    "forbidden",
    "former",
    "historical",
    "rejected",
    "removed",
    "retired",
    "superseded",
}
CURRENT_TOKENS = {"active", "current"}


def normalized_clauses(content: str) -> list[tuple[int, frozenset[str]]]:
    """Return sentence-sized, order-insensitive token sets with source offsets."""

    prepared = re.sub(r"\bD\.1\b", "D_1", content, flags=re.I)
    clauses = []
    for match in re.finditer(r"[^.!?;]+", prepared):
        raw_tokens = re.findall(r"d_1|#[0-9]+|[a-z0-9]+", match.group().casefold())
        tokens = frozenset(
            "d1" if token == "d_1" else TOKEN_CANONICAL.get(token, token)
            for token in raw_tokens
        )
        if tokens:
            clauses.append((match.start(), tokens))
    return clauses


def is_positive_current_assertion(tokens: frozenset[str]) -> bool:
    if tokens & (NEGATION_TOKENS | NON_CURRENT_ASSERTION_TOKENS):
        return False
    return not ({"rather", "than"}.issubset(tokens) or {"instead", "of"}.issubset(tokens))


def is_pre_18_postgres_baseline(tokens: frozenset[str]) -> bool:
    current_baseline = bool(tokens & CURRENT_TOKENS) and "baseline" in tokens
    supported_database = "support" in tokens and "database" in tokens
    return (
        "postgres" in tokens
        and bool(tokens & {"16", "17"})
        and (current_baseline or supported_database)
    )


def is_production_postgres_container(tokens: frozenset[str]) -> bool:
    return (
        "postgres" in tokens
        and "production" in tokens
        and bool(tokens & {"container", "containerized"})
    )


def is_valkey_current_requirement(tokens: frozenset[str]) -> bool:
    current_scope = bool(tokens & CURRENT_TOKENS) and bool(
        tokens & {"deployment", "installation", "integration", "runtime"}
    )
    return (
        "valkey" in tokens
        and current_scope
        and bool(tokens & {"mandatory", "need", "require"})
    )


def is_current_redis_or_valkey_state(tokens: frozenset[str]) -> bool:
    state_role = bool(tokens & {"cache", "queue", "session"}) or {
        "application",
        "state",
    }.issubset(tokens)
    return (
        bool(tokens & {"redis", "valkey"})
        and bool(tokens & CURRENT_TOKENS)
        and state_role
        and bool(tokens & {"back", "backend", "provide", "serve", "use"})
    )


def is_d1_current_host_authority(tokens: frozenset[str]) -> bool:
    return (
        "d1" in tokens
        and bool(tokens & CURRENT_TOKENS)
        and {"production", "host"}.issubset(tokens)
        and bool(tokens & {"authority", "baseline", "contract", "define", "specification"})
    )


def is_universal_production_edge(tokens: frozenset[str]) -> bool:
    universal = bool(tokens & {"all", "any", "every"})
    if (
        "issue89" in tokens
        and "own" in tokens
        and universal
        and {"production", "edge", "mode"}.issubset(tokens)
    ):
        return True
    if "haproxy" not in tokens or "direct" in tokens:
        return False
    public_surface = "public" in tokens and (
        "ingress" in tokens
        or "traffic" in tokens
        or {"viewer", "edge"}.issubset(tokens)
    )
    public_relation = bool(
        tokens & {"at", "edge", "enter", "expose", "handle", "route", "terminate", "through"}
    )
    protected_publication = "protected" in tokens and public_surface and public_relation
    return protected_publication or (universal and public_surface and public_relation)


SEMANTIC_CURRENT_SUPPORT = (
    ("production PostgreSQL container", is_production_postgres_container),
    ("pre-18 PostgreSQL baseline", is_pre_18_postgres_baseline),
    ("Valkey current requirement", is_valkey_current_requirement),
    ("Redis or Valkey current state backing", is_current_redis_or_valkey_state),
    ("D.1 current production-host contract", is_d1_current_host_authority),
    ("universal production-edge authority", is_universal_production_edge),
)

HISTORICAL_STATUS = {
    Path("docs/ci-cloud-conformance.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-host.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-inventory.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-secrets.md"): "> **Status: Historical.**",
    Path("docs/architecture/production-state.md"): "> **Status: Historical.**",
    Path("docs/architecture/decisions/production-edge.md"): "> **Status: Superseded.**",
}


def read(relative: Path) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def discover_markdown_documents(root: Path) -> set[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "*.md",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return {
        Path(value.decode("utf-8"))
        for value in result.stdout.split(b"\0")
        if value
    }


def obsolete_current_support_violations(root: Path) -> list[str]:
    violations = []
    for path, authority in DOCUMENT_AUTHORITY.items():
        if authority not in {Authority.CURRENT_GUIDANCE, Authority.CURRENT_TECHNICAL}:
            continue
        content = (root / path).read_text(encoding="utf-8")
        for claim, pattern in OBSOLETE_CURRENT_SUPPORT.items():
            if match := pattern.search(content):
                line = content.count("\n", 0, match.start()) + 1
                violations.append(f"{path}:{line}: {claim}")
        for claim, predicate in SEMANTIC_CURRENT_SUPPORT:
            for start, tokens in normalized_clauses(content):
                if not is_positive_current_assertion(tokens):
                    continue
                if predicate(tokens):
                    line = content.count("\n", 0, start) + 1
                    violations.append(f"{path}:{line}: {claim}")
                    break
    return violations


class DocumentationCurrentGuidance(unittest.TestCase):
    def authority_fixture(
        self, mutations: dict[Path, tuple[str, str]]
    ) -> tempfile.TemporaryDirectory[str]:
        temporary = tempfile.TemporaryDirectory(prefix="secpal-documentation-authority.")
        root = Path(temporary.name)
        for path in DOCUMENT_AUTHORITY:
            destination = root / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / path, destination)
        for path, (old, new) in mutations.items():
            destination = root / path
            content = destination.read_text(encoding="utf-8")
            self.assertIn(old, content)
            destination.write_text(content.replace(old, new, 1), encoding="utf-8")
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "."], cwd=root, check=True)
        return temporary

    def test_classifier_covers_every_repository_markdown_document(self) -> None:
        discovered = discover_markdown_documents(ROOT)
        self.assertEqual(discovered, set(DOCUMENT_AUTHORITY))

    def test_obsolete_support_wording_is_absent_from_current_guidance(self) -> None:
        self.assertEqual(obsolete_current_support_violations(ROOT), [])

    def test_current_authority_claim_mutations_are_rejected(self) -> None:
        mutations = (
            (
                "Compose execution",
                "Compose execution",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\nRun docker compose for the current deployment.",
                ),
            ),
            (
                "pre-18 production baseline",
                "pre-18 PostgreSQL baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "PostgreSQL 16 is the current SecPal database baseline.",
                ),
            ),
            (
                "PostgreSQL 17 current baseline",
                "pre-18 PostgreSQL baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "PostgreSQL 17 is the current SecPal database baseline.",
                ),
            ),
            (
                "production PostgreSQL container",
                "production PostgreSQL container",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "Run PostgreSQL as a SecPal production container.",
                ),
            ),
            (
                "Valkey current integration",
                "Valkey current requirement",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Valkey is required for the current integration.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Redis current integration",
                "Redis or Valkey current state backing",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Redis backs queues and sessions in the current integration.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Caddy production edge",
                "Caddy production edge",
                Path("docs/architecture/scope.md"),
                (
                    "This document is the deployment documentation index and ownership map.",
                    "Caddy is the production edge for current deployments.\n\n"
                    "This document is the deployment documentation index and ownership map.",
                ),
            ),
            (
                "D.1 current production host",
                "D.1 current production-host contract",
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "D.1 is the current production-host contract",
                ),
            ),
            (
                "Valkey current deployment requirement",
                "Valkey current requirement",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Current deployments require Valkey.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Redis current backend",
                "Redis or Valkey current state backing",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Redis is the backend for the current queue and session stores.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Caddy production termination",
                "Caddy production edge",
                Path("docs/architecture/scope.md"),
                (
                    "This document is the deployment documentation index and ownership map.",
                    "Production traffic is terminated by Caddy.\n\n"
                    "This document is the deployment documentation index and ownership map.",
                ),
            ),
            (
                "D.1 current production host specification",
                "D.1 current production-host contract",
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "D.1 is the current production host specification",
                ),
            ),
            (
                "inverse pre-18 production baseline",
                "pre-18 PostgreSQL baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "The current database baseline is PostgreSQL 16.",
                ),
            ),
            (
                "inverse production PostgreSQL container",
                "production PostgreSQL container",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "SecPal uses a containerized PostgreSQL database in production.",
                ),
            ),
            (
                "Valkey mandatory current deployment",
                "Valkey current requirement",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Valkey is mandatory for current deployments.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "inverse Redis current backend",
                "Redis or Valkey current state backing",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Current queues and sessions use Redis as their backend.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "inverse D.1 current production host baseline",
                "D.1 current production-host contract",
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "The current production-host baseline is defined by D.1.",
                ),
            ),
            (
                "universal issue 89 edge ownership",
                "universal production-edge authority",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n#89 owns all production edge modes.",
                ),
            ),
            (
                "universal HAProxy Viewer Edge",
                "universal production-edge authority",
                Path("docs/architecture/scope.md"),
                (
                    "This document is the deployment documentation index and ownership map.",
                    "HAProxy is the public Viewer Edge for every deployment.\n\n"
                    "This document is the deployment documentation index and ownership map.",
                ),
            ),
            (
                "protected viewer traffic at HAProxy",
                "universal production-edge authority",
                Path("docs/roadmap.md"),
                (
                    "This roadmap distinguishes implementation on current `main`",
                    "Protected deployments terminate public viewer traffic at HAProxy.\n\n"
                    "This roadmap distinguishes implementation on current `main`",
                ),
            ),
            (
                "universal HAProxy Viewer Edge with SecPal qualifier",
                "universal production-edge authority",
                Path("docs/architecture/scope.md"),
                (
                    "This document is the deployment documentation index and ownership map.",
                    "HAProxy is the public Viewer Edge for every SecPal deployment.\n\n"
                    "This document is the deployment documentation index and ownership map.",
                ),
            ),
            (
                "universal public traffic through HAProxy",
                "universal production-edge authority",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\nAll public SecPal traffic enters through HAProxy.",
                ),
            ),
            (
                "active pre-18 production baseline",
                "pre-18 PostgreSQL baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "SecPal's active database baseline is Postgres 16.",
                ),
            ),
            (
                "production PostgreSQL container inverse phrase",
                "production PostgreSQL container",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "Production SecPal runs its PostgreSQL database in a container.",
                ),
            ),
            (
                "Valkey needed by current installations",
                "Valkey current requirement",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Current SecPal installations need Valkey.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "active Redis state backend",
                "Redis or Valkey current state backing",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "The active session and queue backend is Redis.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "D.1 current authority comes from",
                "D.1 current production-host contract",
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "Current production-host authority comes from D.1.",
                ),
            ),
        )
        for name, expected_claim, path, mutation in mutations:
            with self.subTest(name=name), self.authority_fixture({path: mutation}) as temporary:
                root = Path(temporary)
                self.assertEqual(discover_markdown_documents(root), set(DOCUMENT_AUTHORITY))
                violations = obsolete_current_support_violations(root)
                self.assertTrue(
                    any(violation.endswith(f": {expected_claim}") for violation in violations),
                    violations,
                )

    def test_independent_order_variations_are_rejected(self) -> None:
        mutations = (
            (
                "PostgreSQL 17 active baseline",
                "pre-18 PostgreSQL baseline",
                Path("README.md"),
                "Postgres 17 remains SecPal's active database baseline.",
            ),
            (
                "PostgreSQL production container",
                "production PostgreSQL container",
                Path("README.md"),
                "In production, SecPal hosts PostgreSQL inside a container.",
            ),
            (
                "Valkey active installation requirement",
                "Valkey current requirement",
                Path("docs/quadlet-integration.md"),
                "Valkey is needed by active SecPal installations.",
            ),
            (
                "Redis active queue backend",
                "Redis or Valkey current state backing",
                Path("docs/quadlet-integration.md"),
                "Redis serves as the backend for active queues.",
            ),
            (
                "D.1 current host authority",
                "D.1 current production-host contract",
                Path("docs/api-image-consumption.md"),
                "D.1 remains the authority for the current production host.",
            ),
            (
                "universal public HAProxy exposure",
                "universal production-edge authority",
                Path("docs/architecture/scope.md"),
                "Every deployment exposes public traffic through HAProxy.",
            ),
        )
        for name, expected_claim, path, claim in mutations:
            marker = read(path).splitlines()[0]
            mutation = (marker, f"{marker}\n\n{claim}")
            with self.subTest(name=name), self.authority_fixture({path: mutation}) as temporary:
                root = Path(temporary)
                self.assertEqual(discover_markdown_documents(root), set(DOCUMENT_AUTHORITY))
                violations = obsolete_current_support_violations(root)
                self.assertTrue(
                    any(violation.endswith(f": {expected_claim}") for violation in violations),
                    violations,
                )

    def test_historical_and_current_explanatory_controls_remain_permitted(self) -> None:
        controls = (
            ("PostgreSQL 18 baseline", Path("README.md"),
             "PostgreSQL 18 is the current SecPal database baseline."),
            ("production PostgreSQL negation", Path("README.md"),
             "Production PostgreSQL is not a SecPal product container."),
            ("DIRECT Viewer Edge", Path("README.md"),
             "In DIRECT, HAProxy is the public Viewer Edge and Certbot owns Viewer TLS."),
            ("PROTECTED Origin", Path("README.md"),
             "In PROTECTED, HAProxy is the authenticated Origin/backend."),
            ("PROTECTED Viewer Edge negation", Path("README.md"),
             "In PROTECTED, HAProxy is not the public Viewer Edge."),
            ("universal HAProxy negation", Path("README.md"),
             "HAProxy is not the public Viewer Edge for every deployment."),
            ("mode ownership", Path("README.md"),
             "#89 owns DIRECT and #209 owns PROTECTED."),
            ("Valkey negation", Path("docs/quadlet-integration.md"),
             "Current deployments do not require Valkey."),
            ("Redis negation", Path("docs/quadlet-integration.md"),
             "Redis is not used for current queues or sessions."),
            ("integration PostgreSQL container", Path("docs/quadlet-integration.md"),
             "The disposable integration PostgreSQL 18 container is test-only."),
            ("database-backed state", Path("docs/quadlet-integration.md"),
             "The active cache, queues, and sessions are database-backed."),
            ("integration Caddy", Path("docs/quadlet-integration.md"),
             "Caddy is a disposable integration/test gateway."),
            ("Caddy edge negation", Path("docs/architecture/scope.md"),
             "Caddy is not the production edge; it is an integration-only gateway."),
            ("historical state", Path("docs/architecture/production-state.md"),
             "Historical evidence records that Valkey was required, Redis backed queues and "
             "sessions, and PostgreSQL 16 was the production baseline."),
            ("historical PostgreSQL container", Path("docs/architecture/production-state.md"),
             "The historical production PostgreSQL database ran in a container."),
            ("historical Caddy edge", Path("docs/architecture/decisions/production-edge.md"),
             "The superseded record states Caddy is the production edge."),
            ("historical D.1 authority", Path("docs/architecture/production-host.md"),
             "D.1 previously defined the production-host contract."),
        )
        for name, path, claim in controls:
            marker = read(path).splitlines()[0]
            mutation = (marker, f"{marker}\n\n{claim}")
            with self.subTest(name=name), self.authority_fixture({path: mutation}) as temporary:
                root = Path(temporary)
                self.assertEqual(discover_markdown_documents(root), set(DOCUMENT_AUTHORITY))
                self.assertEqual(obsolete_current_support_violations(root), [])
        self.assertEqual(obsolete_current_support_violations(ROOT), [])

    def test_current_guidance_names_the_complete_target_vocabulary(self) -> None:
        current = "\n".join(
            read(path)
            for path, authority in DOCUMENT_AUTHORITY.items()
            if authority is Authority.CURRENT_GUIDANCE
        )
        required = (
            "Rocky Linux 10.2+",
            "SELinux",
            "rootless Podman",
            "Quadlet",
            "host-native PostgreSQL 18",
            "no Valkey",
            "HAProxy",
            "Certbot",
            "nftables",
            "CrowdSec",
            "AppSec",
            "Barman",
            "Borg",
            "Recovery Sets",
            "socketless runtime detection",
        )
        for term in required:
            with self.subTest(term=term):
                self.assertIn(term, current)

    def test_current_edge_navigation_follows_accepted_adr_019_modes(self) -> None:
        navigation = {
            path: read(path)
            for path in (
                Path("README.md"),
                Path("AGENTS.md"),
                Path("docs/architecture/scope.md"),
                Path("docs/roadmap.md"),
                Path("docs/architecture/decisions/production-edge.md"),
            )
        }
        combined = "\n".join(navigation.values())
        for required in (
            ADR_019,
            "DIRECT",
            "PROTECTED",
            "https://github.com/SecPal/deployment/issues/89",
            "https://github.com/SecPal/deployment/issues/209",
        ):
            with self.subTest(required=required):
                self.assertIn(required, combined)

        readme = navigation[Path("README.md")]
        self.assertRegex(readme, r"(?s)DIRECT.{0,500}issues/89")
        self.assertRegex(readme, r"(?s)PROTECTED.{0,500}issues/209")
        self.assertRegex(readme, r"(?is)PROTECTED.{0,500}authenticated Origin/backend")
        self.assertRegex(
            readme,
            r"(?is)PROTECTED.{0,500}not\s+(?:the\s+)?public\s+Viewer\s+Edge",
        )

        agents = navigation[Path("AGENTS.md")]
        self.assertIn(ADR_019, agents)
        self.assertRegex(agents, r"(?s)DIRECT.{0,500}#89")
        self.assertRegex(agents, r"(?s)PROTECTED.{0,500}#209")

        old_edge = navigation[Path("docs/architecture/decisions/production-edge.md")][
            :1_500
        ]
        self.assertIn(ADR_019, old_edge)
        self.assertIn("DIRECT", old_edge)
        self.assertIn("PROTECTED", old_edge)
        self.assertNotIn("owned solely by", old_edge)

        for stale in (
            "HAProxy alone owns public ingress",
            "#89 owns all production edge modes",
            "HAProxy is the public Viewer Edge for every deployment",
            "Protected deployments terminate public viewer traffic at HAProxy",
        ):
            with self.subTest(stale=stale):
                self.assertNotIn(stale, combined)

    def test_superseded_records_have_bounded_status_markers(self) -> None:
        for path, marker in HISTORICAL_STATUS.items():
            with self.subTest(path=path):
                self.assertIn(marker, read(path)[:1_000])

        old_edge = read(Path("docs/architecture/decisions/production-edge.md"))[:1_000]
        self.assertIn(ADR_019, old_edge)
        self.assertIn("https://github.com/SecPal/deployment/issues/89", old_edge)
        self.assertIn("https://github.com/SecPal/deployment/issues/209", old_edge)

    def test_current_integration_states_its_two_implementation_boundaries(self) -> None:
        integration = read(Path("docs/quadlet-integration.md"))
        for current_fact in (
            "PostgreSQL 18.6",
            "/var/lib/postgresql/18/docker",
            "CACHE_STORE=database",
            "QUEUE_CONNECTION=database",
            "SESSION_DRIVER=database",
            "exactly one `activity-hash-chain` worker",
            "one scheduler",
            "not the production edge",
        ):
            with self.subTest(current_fact=current_fact):
                self.assertIn(current_fact, integration)
        self.assertRegex(integration, r"one\s+explicit migration container")
        self.assertIn("https://github.com/SecPal/deployment/issues/119", integration)
        self.assertIn("blocked by #118", integration)


if __name__ == "__main__":
    unittest.main(verbosity=2)
