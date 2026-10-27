import ast
from pathlib import Path

import poi.verify

ALLOWED = {"poi", "poi.canonical", "poi.lthash", "poi.evidence", "poi.policy", "poi.seal"}


def test_verifier_imports_only_allowed_modules():
    tree = ast.parse(Path(poi.verify.__file__).read_text())
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("poi"):
            mods |= {node.module} if node.module != "poi" else {f"poi.{a.name}" for a in node.names}
        elif isinstance(node, ast.Import):
            mods |= {a.name for a in node.names if a.name.startswith("poi")}
    assert mods <= ALLOWED, mods - ALLOWED
