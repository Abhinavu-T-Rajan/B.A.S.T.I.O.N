from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SRC_BASTION = REPO_ROOT / "src" / "bastion"


def _extract_imports(file_path: Path) -> list[str]:
    """Parse a python file using AST and return all imported module names."""
    tree = ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
    imported_modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_modules.append(node.module)
    return imported_modules


def test_core_does_not_import_infrastructure() -> None:
    """Enforce that core domain packages never import infrastructure or concrete drivers."""
    core_dir = SRC_BASTION / "core"
    if not core_dir.exists():
        return

    forbidden_prefixes = (
        "bastion.infrastructure",
        "bastion.cli",
        "bastion.firewall.nftables",
        "bastion.storage.sqlite",
        "sqlite3",
        "subprocess",
        "argparse",
    )

    for py_file in core_dir.rglob("*.py"):
        imports = _extract_imports(py_file)
        for imp in imports:
            for forbidden in forbidden_prefixes:
                assert not (imp == forbidden or imp.startswith(f"{forbidden}.")), (
                    f"Architecture Violation in {py_file.relative_to(REPO_ROOT)}: "
                    f"Core module illegally imports '{imp}'"
                )


def test_detectors_do_not_import_storage_or_firewall() -> None:
    """Enforce that behavioral threat detectors have zero coupling to storage, firewall, or CLI."""
    detection_dir = SRC_BASTION / "detection"
    forbidden_prefixes = (
        "bastion.storage",
        "bastion.firewall",
        "bastion.cli",
        "bastion.daemon",
        "sqlite3",
    )

    for py_file in detection_dir.glob("*.py"):
        if py_file.name == "__init__.py":
            continue
        imports = _extract_imports(py_file)
        for imp in imports:
            for forbidden in forbidden_prefixes:
                assert not (imp == forbidden or imp.startswith(f"{forbidden}.")), (
                    f"Architecture Violation in {py_file.relative_to(REPO_ROOT)}: "
                    f"Detector illegally imports '{imp}'"
                )


def test_telemetry_adapters_do_not_import_response_or_storage() -> None:
    """Enforce that telemetry normalizers/adapters do not depend on defense response or database."""
    telemetry_dir = SRC_BASTION / "infrastructure" / "telemetry"
    if not telemetry_dir.exists():
        return

    forbidden_prefixes = (
        "bastion.response",
        "bastion.storage",
        "bastion.firewall",
        "bastion.cli",
    )

    for py_file in telemetry_dir.rglob("*.py"):
        imports = _extract_imports(py_file)
        for imp in imports:
            for forbidden in forbidden_prefixes:
                assert not (imp == forbidden or imp.startswith(f"{forbidden}.")), (
                    f"Architecture Violation in {py_file.relative_to(REPO_ROOT)}: "
                    f"Telemetry adapter illegally imports '{imp}'"
                )


def test_cli_does_not_import_raw_database_drivers() -> None:
    """Enforce that CLI delegates to application services and does not import raw sqlite3."""
    cli_file = SRC_BASTION / "cli.py"
    imports = _extract_imports(cli_file)
    assert "sqlite3" not in imports, "CLI illegally imports raw sqlite3 driver"
