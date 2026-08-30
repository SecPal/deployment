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
    "production PostgreSQL container": re.compile(
        r"\b(?:"
        r"(?:run|start|deploy|use)\s+(?:PostgreSQL|Postgres)\s+as\s+"
        r"(?:a\s+)?(?:SecPal\s+)?production(?:\s+database)?\s+container"
        r"|(?:production|SecPal\s+production)\s+(?:PostgreSQL|Postgres)"
        r"(?:\s+database)?\s+container"
        r"|(?:PostgreSQL|Postgres)\s+(?:container|containerized)"
        r"(?:\s+database)?\s+(?:for|as)\s+(?:a\s+)?(?:SecPal\s+)?production"
        r"|(?:SecPal|current\s+deployments?)\s+(?:runs?|uses?|hosts?)\s+"
        r"(?:a\s+)?containerized\s+(?:PostgreSQL|Postgres)(?:\s+database)?\s+"
        r"(?:in|for)\s+production"
        r")\b",
        re.I,
    ),
    "pre-18 PostgreSQL baseline": re.compile(
        r"\b(?:"
        r"(?:PostgreSQL|Postgres)\s+(?:16|17)\s+is\s+the\s+"
        r"(?:(?:current|production)\s+)?(?:SecPal\s+)?(?:database\s+)?"
        r"(?:baseline|supported\s+baseline)"
        r"|(?:the\s+)?(?:current|production)\s+(?:SecPal\s+)?"
        r"(?:database\s+)?(?:baseline|supported\s+baseline)\s+is\s+"
        r"(?:PostgreSQL|Postgres)\s+(?:16|17)"
        r")\b",
        re.I,
    ),
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
    "Valkey current requirement": re.compile(
        r"\b(?:"
        r"(?:Valkey|Redis)\s+(?:is|are)\s+(?:required|current|mandatory)"
        r"|(?:current\s+)?(?:deployments?|integration|runtime)\s+require(?:s)?\s+"
        r"(?:Valkey|Redis)"
        r")\b",
        re.I,
    ),
    "Redis or Valkey current state backing": re.compile(
        r"\b(?:Valkey|Redis)\s+(?:"
        r"(?:backs?|provides?)\s+(?:the\s+)?(?:current\s+)?"
        r"(?:application\s+state|cache|queues?|sessions?)(?:\s+and\s+"
        r"(?:the\s+)?(?:current\s+)?(?:application\s+state|cache|queues?|sessions?))?"
        r"(?:\s+stores?)?"
        r"|is\s+(?:the\s+)?(?:current\s+)?(?:backend|backing\s+store)\s+for\s+"
        r"(?:the\s+)?(?:current\s+)?(?:application\s+state|cache|queues?|sessions?)"
        r"(?:\s+and\s+(?:the\s+)?(?:current\s+)?"
        r"(?:application\s+state|cache|queues?|sessions?))?(?:\s+stores?)?"
        r")\b|\b(?:current\s+)?(?:application\s+state|cache|queues?|sessions?)"
        r"(?:\s+and\s+(?:the\s+)?(?:current\s+)?"
        r"(?:application\s+state|cache|queues?|sessions?))?\s+"
        r"(?:uses?|use)\s+(?:Valkey|Redis)\s+as\s+(?:the|their)\s+backend\b",
        re.I,
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
    "D.1 current production-host contract": re.compile(
        r"\b(?:"
        r"D\.1\s+(?:now\s+)?(?:defines|is)\s+(?:the\s+)?"
        r"(?:current\s+)?production[- ]host\s+"
        r"(?:contract|specification|authority|baseline)"
        r"|(?:the\s+)?current\s+production[- ]host\s+"
        r"(?:contract|specification|authority|baseline)\s+is\s+"
        r"(?:defined|owned)\s+by\s+D\.1"
        r")\b",
        re.I,
    ),
    "universal production-edge authority": re.compile(
        r"(?:"
        r"#89\s+owns\s+(?:all|every)\s+production[- ]edge\s+modes?"
        r"|HAProxy\s+is\s+the\s+public\s+Viewer\s+Edge\s+for\s+"
        r"(?:all|every)\s+deployments?"
        r"|PROTECTED\s+deployments?\s+(?:terminate|route|handle)\s+"
        r"public\s+Viewer\s+traffic\s+at\s+HAProxy"
        r")",
        re.I,
    ),
    "old implementation status": re.compile(
        r"\bD\.1 host contract,\s+D\.1a integration-runtime parity, and D\.2"
        r"[^.]{0,100}\bare implemented\b",
        re.I | re.S,
    ),
}

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
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\nRun docker compose for the current deployment.",
                ),
            ),
            (
                "pre-18 production baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "PostgreSQL 16 is the current SecPal database baseline.",
                ),
            ),
            (
                "PostgreSQL 17 current baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "PostgreSQL 17 is the current SecPal database baseline.",
                ),
            ),
            (
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
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Valkey is required for the current integration.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Redis current integration",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Redis backs queues and sessions in the current integration.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
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
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "D.1 is the current production-host contract",
                ),
            ),
            (
                "Valkey current deployment requirement",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Current deployments require Valkey.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Redis current backend",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Redis is the backend for the current queue and session stores.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "Caddy production termination",
                Path("docs/architecture/scope.md"),
                (
                    "This document is the deployment documentation index and ownership map.",
                    "Production traffic is terminated by Caddy.\n\n"
                    "This document is the deployment documentation index and ownership map.",
                ),
            ),
            (
                "D.1 current production host specification",
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "D.1 is the current production host specification",
                ),
            ),
            (
                "inverse pre-18 production baseline",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "The current database baseline is PostgreSQL 16.",
                ),
            ),
            (
                "inverse production PostgreSQL container",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n"
                    "SecPal uses a containerized PostgreSQL database in production.",
                ),
            ),
            (
                "Valkey mandatory current deployment",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Valkey is mandatory for current deployments.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "inverse Redis current backend",
                Path("docs/quadlet-integration.md"),
                (
                    "This is the active disposable integration runtime delivered by",
                    "Current queues and sessions use Redis as their backend.\n\n"
                    "This is the active disposable integration runtime delivered by",
                ),
            ),
            (
                "inverse D.1 current production host baseline",
                Path("docs/api-image-consumption.md"),
                (
                    "At Phase C completion, Phase D had not started. D.1 subsequently defined an\n"
                    "earlier production-host contract that is now historical.",
                    "The current production-host baseline is defined by D.1.",
                ),
            ),
            (
                "universal issue 89 edge ownership",
                Path("README.md"),
                (
                    "# SecPal Deployment",
                    "# SecPal Deployment\n\n#89 owns all production edge modes.",
                ),
            ),
            (
                "universal HAProxy Viewer Edge",
                Path("docs/architecture/scope.md"),
                (
                    "This document is the deployment documentation index and ownership map.",
                    "HAProxy is the public Viewer Edge for every deployment.\n\n"
                    "This document is the deployment documentation index and ownership map.",
                ),
            ),
            (
                "protected viewer traffic at HAProxy",
                Path("docs/roadmap.md"),
                (
                    "This roadmap distinguishes implementation on current `main`",
                    "Protected deployments terminate public viewer traffic at HAProxy.\n\n"
                    "This roadmap distinguishes implementation on current `main`",
                ),
            ),
        )
        for name, path, mutation in mutations:
            with self.subTest(name=name), self.authority_fixture({path: mutation}) as temporary:
                root = Path(temporary)
                self.assertEqual(discover_markdown_documents(root), set(DOCUMENT_AUTHORITY))
                self.assertNotEqual(obsolete_current_support_violations(root), [])

    def test_historical_and_current_explanatory_controls_remain_permitted(self) -> None:
        mutations = {
            Path("README.md"): (
                "# SecPal Deployment",
                "# SecPal Deployment\n\n"
                "PostgreSQL 18 is the current SecPal database baseline.\n"
                "Production PostgreSQL is not a SecPal container.\n"
                "In DIRECT, HAProxy is the public Viewer Edge and Certbot owns Viewer TLS.\n"
                "In PROTECTED, HAProxy is the authenticated Origin/backend, not the public "
                "Viewer Edge.\n"
                "#89 owns DIRECT and #209 owns PROTECTED.",
            ),
            Path("docs/quadlet-integration.md"): (
                "This is the active disposable integration runtime delivered by",
                "Current deployments do not require Valkey.\n"
                "Redis is not used for current queues or sessions.\n"
                "The disposable integration PostgreSQL container is test-only.\n"
                "The cache is database-backed, queues use the database connection, and sessions "
                "use the database.\n"
                "Caddy is a disposable integration/test gateway.\n\n"
                "This is the active disposable integration runtime delivered by",
            ),
            Path("docs/architecture/production-state.md"): (
                "This document describes the historical D.2 persistence and product-role contracts.",
                "Historical evidence records that Valkey was required, Redis backed queues and "
                "sessions, and PostgreSQL 16 was the production baseline.\n\n"
                "This document describes the historical D.2 persistence and product-role contracts.",
            ),
            Path("docs/architecture/decisions/production-edge.md"): (
                "This ADR was accepted for the former single-host production reference.",
                "The superseded record states Caddy is the production edge.\n\n"
                "This ADR was accepted for the former single-host production reference.",
            ),
            Path("docs/architecture/production-host.md"): (
                "This document defines the provider-neutral admission contract",
                "D.1 previously defined the production-host contract.\n\n"
                "This document defines the provider-neutral admission contract",
            ),
        }
        with self.authority_fixture(mutations) as temporary:
            root = Path(temporary)
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
