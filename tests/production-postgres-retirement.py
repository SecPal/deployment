#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 SecPal Contributors
# SPDX-License-Identifier: MIT

"""Contract tests for retirement of the D.2 PostgreSQL product container."""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path
import re
import sys
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
RENDERER_PATH = ROOT / "scripts" / "render-production-quadlets.py"
CONTRACT_PATH = ROOT / "config" / "production" / "state-contract.json"
QUADLET_ROOT = ROOT / "config" / "production" / "quadlet"
CURRENT_EXECUTION_PATHS = (
    ROOT / ".github" / "workflows" / "local-integration.yml",
    ROOT / "scripts" / "preflight.sh",
    ROOT / "tests" / "production-state-contract.py",
    ROOT / "tests" / "production-state-native-lifecycle.sh",
    ROOT / "tests" / "repository-contract.sh",
)
DELETED_PATHS = (
    ROOT / "config" / "production" / "quadlet" / "secpal-postgres-init.container",
    ROOT / "config" / "production" / "quadlet" / "secpal-postgres.container",
    ROOT / "scripts" / "production-postgres-entrypoint.sh",
)
POSTGRES_IMAGE = re.compile(
    r"(?i)(?:[a-z0-9.-]+/)+(?:[a-z0-9._-]+/)*"
    r"[a-z0-9._-]*postgres(?:ql)?(?:-server)?[a-z0-9._-]*(?=[:@])"
    r"|(?<![a-z0-9._-])postgres(?:ql)?(?:-server)?(?=[:@])"
)
SERVER_ENVIRONMENT = re.compile(r"(?m)^\s*(?:Environment=)?(?:PGDATA|PG_MAJOR|PG_VERSION)=")
SERVER_DATA_PATH = re.compile(r"/var/lib/postgresql(?:/|\b)")
CONTAINER_COMMAND = re.compile(r"(?i)\b(?:Entrypoint|Exec|Command)\s*=")
CONTAINER_SERVER_COMMAND = re.compile(
    r"(?i)\b(?:Entrypoint|Exec|Command)\s*=\s*(?:\[['\"]*)?"
    r"(?:/[^\s'\",\]]+/)?(?:postgres|initdb|pg_ctl)(?=[\s'\",\]]|$)"
)
SHELL_EXEC = re.compile(
    r"(?m)(?:^|[;&|])\s*(?:exec\s+)?(?:/[^\s]+/)?"
    r"(?:postgres|initdb|pg_ctl)(?=\s+(?![=])|$)"
)
PYTHON_SERVER_COMMAND = re.compile(
    r"[\[(]\s*['\"](?:/[^'\"]+/)?(?:postgres|initdb|pg_ctl)['\"]\s*,"
)
DIRECT_CONTAINER = re.compile(
    r"(?i)\b(?:podman|docker)(?:\s+|['\"]\s*,\s*['\"])(?:run|create)\b"
)
CLIENT_ONLY = re.compile(r"(?<![a-z0-9_])(?:psql|pg_isready|pg_dump|pg_restore)(?![a-z0-9_-])")
WORKFLOW_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def _code_lines(content: str) -> list[str]:
    return [
        line
        for line in content.replace("\\\n", " ").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _server_execution_present(content: str, *, shell: bool = True) -> bool:
    for line in _code_lines(content):
        if CONTAINER_SERVER_COMMAND.search(line):
            return True
        if PYTHON_SERVER_COMMAND.search(line):
            return True
        if shell and SHELL_EXEC.search(line):
            return True
    return False


def postgres_server_container_indicators(content: str) -> set[str]:
    """Return semantic PostgreSQL server indicators in one container definition."""
    indicators: set[str] = set()
    image_values = [
        line.split("=", 1)[1].strip().strip("'\"")
        for line in _code_lines(content)
        if line.lstrip().startswith("Image=")
    ]
    strong_server_semantics = _server_execution_present(content)
    if strong_server_semantics:
        indicators.add("server executable or initializer")
    if SERVER_ENVIRONMENT.search(content):
        indicators.add("server-only PostgreSQL environment")
    if SERVER_DATA_PATH.search(content):
        indicators.add("PostgreSQL server data path")
    for image in image_values:
        if POSTGRES_IMAGE.search(image):
            commands = "\n".join(
                line for line in _code_lines(content) if CONTAINER_COMMAND.search(line)
            )
            if not (CLIENT_ONLY.search(commands) and not indicators):
                indicators.add("PostgreSQL server image")
    return indicators


def production_execution_indicators(
    content: str, *, shell: bool = True, construction_authority: bool = False
) -> set[str]:
    """Return server-container indicators in production code or acceptance wiring."""
    indicators: set[str] = set()
    normalized = content.replace("\\\n", " ")
    image_reference = POSTGRES_IMAGE.search(normalized)
    server_execution = _server_execution_present(normalized, shell=shell)
    server_state = SERVER_ENVIRONMENT.search(normalized) or SERVER_DATA_PATH.search(normalized)
    client_only = CLIENT_ONLY.search(normalized) and not server_execution and not server_state

    for line in _code_lines(normalized):
        if not DIRECT_CONTAINER.search(line):
            continue
        line_server = _server_execution_present(line, shell=shell)
        line_state = SERVER_ENVIRONMENT.search(line) or SERVER_DATA_PATH.search(line)
        line_client = CLIENT_ONLY.search(line) and not line_server and not line_state
        if line_server or line_state or (POSTGRES_IMAGE.search(line) and not line_client):
            indicators.add("direct PostgreSQL server container execution")
    if server_execution:
        indicators.add("PostgreSQL server executable or initializer")
    if server_state:
        indicators.add("PostgreSQL server-only state")
    if construction_authority and image_reference and not client_only:
        indicators.add("PostgreSQL server image construction")
    return indicators


def _workflow_environment(value: object) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {
        name: item
        for name, item in value.items()
        if isinstance(name, str) and isinstance(item, str)
    }


def _resolve_workflow_variables(command: str, environment: dict[str, str]) -> str:
    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return environment.get(name, match.group(0))

    return WORKFLOW_VARIABLE.sub(replace, command)


def workflow_execution_indicators(content: str) -> set[str]:
    """Resolve simple workflow environment use inside direct execution steps."""
    loaded = yaml.safe_load(content)
    if not isinstance(loaded, dict) or not isinstance(loaded.get("jobs"), dict):
        return set()
    indicators: set[str] = set()
    for job in loaded["jobs"].values():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        job_environment = _workflow_environment(job.get("env"))
        for step in job["steps"]:
            if not isinstance(step, dict) or not isinstance(step.get("run"), str):
                continue
            environment = {**job_environment, **_workflow_environment(step.get("env"))}
            resolved = _resolve_workflow_variables(step["run"], environment)
            indicators.update(production_execution_indicators(resolved))
    return indicators


def _module_constants(path: Path) -> dict[str, str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    constants: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if isinstance(statement.value, ast.Constant) and isinstance(statement.value.value, str):
                for target in targets:
                    if isinstance(target, ast.Name):
                        constants[target.id] = statement.value.value
    return constants


def _local_module_path(renderer_path: Path, module: str | None) -> Path | None:
    if not module or "." in module:
        return None
    candidate = renderer_path.parent / f"{module}.py"
    return candidate if candidate.is_file() else None


def _resolve_image_expression(
    expression: ast.expr,
    values: dict[str, str],
    modules: dict[str, dict[str, str]],
) -> str | None:
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return expression.value
    if isinstance(expression, ast.Name):
        return values.get(expression.id)
    if isinstance(expression, ast.Attribute) and isinstance(expression.value, ast.Name):
        return modules.get(expression.value.id, {}).get(expression.attr)
    return None


def _container_constructors(tree: ast.Module) -> dict[str, int]:
    constructors: dict[str, int] = {}
    for statement in tree.body:
        if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = [argument.arg for argument in statement.args.args]
        if "image" not in arguments:
            continue
        fragments = {
            node.value
            for node in ast.walk(statement)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        if any("ContainerName=" in fragment for fragment in fragments) and any(
            "Image=" in fragment for fragment in fragments
        ):
            constructors[statement.name] = arguments.index("image")
    return constructors


def renderer_construction_indicators(content: str, renderer_path: Path) -> set[str]:
    """Find PostgreSQL image values flowing into direct renderer constructors."""
    tree = ast.parse(content, filename=str(renderer_path))
    constructors = _container_constructors(tree)
    values: dict[str, str] = {}
    modules: dict[str, dict[str, str]] = {}

    for statement in tree.body:
        if isinstance(statement, ast.ImportFrom):
            module_path = _local_module_path(renderer_path, statement.module)
            if module_path is None:
                continue
            constants = _module_constants(module_path)
            for alias in statement.names:
                if alias.name in constants:
                    values[alias.asname or alias.name] = constants[alias.name]
        elif isinstance(statement, ast.Import):
            for alias in statement.names:
                module_path = _local_module_path(renderer_path, alias.name)
                if module_path is not None:
                    modules[alias.asname or alias.name] = _module_constants(module_path)

    assignments = [
        node
        for node in tree.body
        if isinstance(node, (ast.Assign, ast.AnnAssign))
    ]
    for _ in range(len(assignments) + 1):
        changed = False
        for statement in assignments:
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            resolved = _resolve_image_expression(statement.value, values, modules)
            if resolved is None:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and values.get(target.id) != resolved:
                    values[target.id] = resolved
                    changed = True
        if not changed:
            break

    indicators: set[str] = set()
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        if not isinstance(call.func, ast.Name) or call.func.id not in constructors:
            continue
        image_position = constructors[call.func.id]
        image_expression = next(
            (keyword.value for keyword in call.keywords if keyword.arg == "image"),
            call.args[image_position] if len(call.args) > image_position else None,
        )
        if image_expression is None:
            continue
        image = _resolve_image_expression(image_expression, values, modules)
        if image is not None and POSTGRES_IMAGE.search(image):
            indicators.add("latent PostgreSQL server image construction")
    return indicators


def production_helper_paths(root: Path, authority_content: str) -> list[Path]:
    """Select production helpers without depending on a database filename."""
    scripts = root / "scripts"
    return sorted(
        path
        for path in scripts.iterdir()
        if path.is_file()
        and ("production" in path.name or path.name in authority_content)
    )


def load_renderer():
    spec = importlib.util.spec_from_file_location("production_renderer", RENDERER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load production Quadlet renderer")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProductionPostgresRetirementTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.renderer = load_renderer()
        cls.contract = cls.renderer.load_contract(CONTRACT_PATH)

    def test_renderer_cannot_emit_a_postgres_product_container(self) -> None:
        rendered = self.renderer.build_units(self.contract)
        for name, content in rendered.items():
            if not name.endswith(".container"):
                continue
            with self.subTest(unit=name):
                self.assertEqual(postgres_server_container_indicators(content), set())
        self.assertEqual(
            production_execution_indicators(
                RENDERER_PATH.read_text(encoding="utf-8"),
                shell=False,
                construction_authority=True,
            ),
            set(),
        )
        self.assertEqual(
            renderer_construction_indicators(
                RENDERER_PATH.read_text(encoding="utf-8"), RENDERER_PATH
            ),
            set(),
        )

    def test_checked_production_quadlets_have_no_postgres_units(self) -> None:
        checked = {
            path.name: path.read_text(encoding="utf-8")
            for path in QUADLET_ROOT.iterdir()
            if path.is_file()
        }
        for name, content in checked.items():
            if not name.endswith(".container"):
                continue
            with self.subTest(unit=name):
                self.assertEqual(postgres_server_container_indicators(content), set())

    def test_current_acceptance_cannot_reactivate_the_retired_path(self) -> None:
        for path in CURRENT_EXECUTION_PATHS:
            content = path.read_text(encoding="utf-8")
            with self.subTest(path=path.relative_to(ROOT)):
                indicators = production_execution_indicators(content)
                if path.suffix in {".yaml", ".yml"}:
                    indicators.update(workflow_execution_indicators(content))
                self.assertEqual(indicators, set())

    def test_no_legacy_launcher_or_reactivation_switch_exists(self) -> None:
        for path in DELETED_PATHS:
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertFalse(path.exists())
        authority_content = RENDERER_PATH.read_text(encoding="utf-8") + "\n" + "\n".join(
            path.read_text(encoding="utf-8") for path in QUADLET_ROOT.iterdir() if path.is_file()
        )
        for path in production_helper_paths(ROOT, authority_content):
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertEqual(
                    production_execution_indicators(
                        path.read_text(encoding="utf-8"),
                        shell=path.suffix == ".sh",
                        construction_authority=True,
                    ),
                    set(),
                )

    def test_renamed_checked_quadlet_cannot_restore_the_server(self) -> None:
        renamed = """[Container]
ContainerName=secpal-database
Image=registry.example.invalid/vendor/database@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Label=org.secpal.role=database
Entrypoint=[\"/usr/bin/postgres\"]
"""
        self.assertNotEqual(postgres_server_container_indicators(renamed), set())
        server_signals = (
            "[Container]\nImage=docker.io/library/postgres:16\n",
            "[Container]\nExec=initdb --pgdata /state\n",
            "[Container]\nExec=pg_ctl start --pgdata /state\n",
            "[Container]\nEnvironment=PGDATA=/state\n",
            "[Container]\nMount=type=bind,source=/state,target=/var/lib/postgresql/data\n",
        )
        for content in server_signals:
            with self.subTest(server_signal=content.splitlines()[1]):
                self.assertNotEqual(postgres_server_container_indicators(content), set())

    def test_indirect_workflow_cannot_start_the_server(self) -> None:
        workflow = """- name: Start production database container
  run: podman run --detach --name secpal-database docker.io/library/postgres@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74
"""
        self.assertNotEqual(production_execution_indicators(workflow), set())

    def test_renamed_production_launcher_cannot_restore_the_server(self) -> None:
        launcher = """#!/bin/bash
set -euo pipefail
exec /usr/bin/postgres -D /var/lib/postgresql/data
"""
        self.assertNotEqual(production_execution_indicators(launcher), set())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scripts = root / "scripts"
            scripts.mkdir()
            renamed = scripts / "database-entrypoint.sh"
            renamed.write_text(launcher, encoding="utf-8")
            renamed.chmod(0o700)
            authority = (
                "Mount=type=bind,source=/srv/secpal/config/runtime/database-entrypoint.sh,"
                "target=/run/secpal/bootstrap/database-entrypoint.sh,ro=true"
            )
            self.assertEqual(production_helper_paths(root, authority), [renamed])

    def test_neutral_compatibility_branch_cannot_restore_the_server(self) -> None:
        renderer_branch = """if os.environ.get(\"SECPAL_DATABASE_MODE\"):
    units[\"secpal-database.container\"] = 'Entrypoint=[\"/usr/bin/postgres\"]'
"""
        self.assertNotEqual(production_execution_indicators(renderer_branch), set())

    def test_workflow_step_environment_cannot_hide_the_server_image(self) -> None:
        workflow = """jobs:
  contract:
    steps:
      - name: Start production database container from reviewed variable
        env:
          DATABASE_IMAGE: docker.io/library/postgres@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74
        run: |
          podman run --detach --name secpal-db \"${DATABASE_IMAGE}\"
"""
        self.assertNotEqual(workflow_execution_indicators(workflow), set())
        job_environment = """jobs:
  contract:
    env:
      DATABASE_IMAGE: docker.io/library/postgres@sha256:38471f330eb885e04de130b768d6db4e10469e2311879c7e5c699f6d2d8a1c74
    steps:
      - run: podman run --detach --name secpal-db "$DATABASE_IMAGE"
"""
        self.assertNotEqual(workflow_execution_indicators(job_environment), set())

    def test_imported_image_cannot_hide_a_latent_renderer_branch(self) -> None:
        renderer_branch = RENDERER_PATH.read_text(encoding="utf-8") + """
from integration_runtime_contract import POSTGRES_IMAGE
if os.environ.get(\"SECPAL_DATABASE_MODE\"):
    units[\"secpal-database.container\"] = common_container(
        contract, \"valkey\", POSTGRES_IMAGE, instance=\"database\"
    )
"""
        self.assertNotEqual(
            renderer_construction_indicators(renderer_branch, RENDERER_PATH),
            set(),
        )
        qualified_branch = RENDERER_PATH.read_text(encoding="utf-8") + """
import integration_runtime_contract as runtime_contract
DATABASE_IMAGE = runtime_contract.POSTGRES_IMAGE
if os.environ.get(\"SECPAL_DATABASE_MODE\"):
    units[\"secpal-database.container\"] = common_container(
        contract, \"valkey\", DATABASE_IMAGE, instance=\"database\"
    )
"""
        self.assertNotEqual(
            renderer_construction_indicators(qualified_branch, RENDERER_PATH),
            set(),
        )

    def test_client_and_application_postgres_references_remain_valid(self) -> None:
        application = """[Container]
Image=ghcr.io/secpal/api@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Environment=DB_HOST=postgres
Mount=type=bind,source=/run/secpal/secrets/api/postgres-password,target=/run/secpal/secrets/api/postgres-password,ro=true
Exec=php artisan queue:work
"""
        client = """#!/bin/bash
set -euo pipefail
exec /usr/bin/psql --host postgres --command 'SELECT 1'
/usr/bin/pg_isready --host postgres
"""
        client_container = """[Container]
Image=docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Entrypoint=[\"/usr/bin/psql\"]
Exec=--host postgres --command SELECT-1
"""
        self.assertEqual(postgres_server_container_indicators(application), set())
        self.assertEqual(production_execution_indicators(client), set())
        self.assertEqual(postgres_server_container_indicators(client_container), set())
        unused_workflow_image = """jobs:
  contract:
    steps:
      - env:
          DATABASE_IMAGE: docker.io/library/postgres@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        run: printf 'client configuration only\\n'
"""
        self.assertEqual(workflow_execution_indicators(unused_workflow_image), set())
        unused_renderer_import = RENDERER_PATH.read_text(encoding="utf-8") + """
from integration_runtime_contract import POSTGRES_IMAGE as CLIENT_IMAGE
CLIENT_COMMAND = (\"psql\", \"--host\", \"postgres\")
"""
        self.assertEqual(
            renderer_construction_indicators(unused_renderer_import, RENDERER_PATH), set()
        )
        helpers = production_helper_paths(ROOT, RENDERER_PATH.read_text(encoding="utf-8"))
        self.assertNotIn(ROOT / "scripts" / "quadlet-integration.py", helpers)
        self.assertNotIn(ROOT / "scripts" / "integration_runtime_contract.py", helpers)


if __name__ == "__main__":
    unittest.main()
