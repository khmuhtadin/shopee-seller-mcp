"""Publication gates for the distributable catalog."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import pytest

from shopee_mcp.catalog import Catalog, CatalogError
from shopee_mcp.policy import Policy


PUBLIC_ROOT = Path(__file__).resolve().parents[1] / "public_catalog"


def test_public_catalog_is_self_contained_and_preserves_tool_coverage():
    catalog = Catalog(PUBLIC_ROOT)
    coverage = catalog.coverage()
    assert (coverage["discovered"], coverage["active"], coverage["retired"]) == (450, 410, 40)
    assert (coverage["implemented"], coverage["unresolved"]) == (406, 4)
    assert len(catalog.endpoints) == 406
    assert len(catalog.tools(Policy("test"))) == 237


def test_public_catalog_has_no_copied_examples_or_private_references():
    for path in PUBLIC_ROOT.rglob("*.json"):
        content = path.read_text()
        assert not re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", content, re.IGNORECASE), path
        assert not re.search(r"[\u3040-\u30ff]", content), path
        assert "/Users/" not in content, path
        if path.parent.name == "endpoints":
            endpoint = json.loads(content)
            assert not {"source", "fixture", "contract_fixture", "tests", "permissions", "regions"} & endpoint.keys()


def test_public_catalog_detects_endpoint_tampering(tmp_path):
    copied = tmp_path / "catalog"
    shutil.copytree(PUBLIC_ROOT, copied)
    endpoint = copied / "endpoints" / "v2.shop.get_shop_info.json"
    endpoint.write_bytes(endpoint.read_bytes() + b"\n")
    with pytest.raises(CatalogError, match="hash mismatch"):
        Catalog(copied)
