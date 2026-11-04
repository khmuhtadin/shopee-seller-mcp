"""Check built archives for private inputs and unexpected publication content."""

from __future__ import annotations

import argparse
import json
import re
import tarfile
import zipfile
from pathlib import Path


PRIVATE_NAMES = frozenset({"catalog", "tmp", "tests", "tools", "local-data", "PUBLICATION_REVIEW.md"})
EMAIL = re.compile(rb"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
HOME_PATH = re.compile(rb"/(?:Users|home)/[^/\s\"']+")
PRIVATE_KEY = re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----")


def _members(path: Path):
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if not name.endswith("/"):
                    yield name, archive.read(name)
    elif path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as archive:
            for member in archive.getmembers():
                if member.isfile():
                    stream = archive.extractfile(member)
                    assert stream is not None
                    yield member.name, stream.read()
    else:
        raise ValueError(f"Unsupported distribution: {path}")


def check(path: Path) -> int:
    endpoints = 0
    for name, content in _members(path):
        parts = Path(name).parts
        if path.name.endswith(".tar.gz"):
            parts = parts[1:]
        if any(part in PRIVATE_NAMES for part in parts) or any(part in {"__pycache__", ".venv"} for part in parts):
            raise ValueError(f"Private path in distribution: {name}")
        if name.endswith((".pyc", ".env", ".DS_Store")):
            raise ValueError(f"Local file in distribution: {name}")
        if EMAIL.search(content) or HOME_PATH.search(content) or PRIVATE_KEY.search(content):
            raise ValueError(f"Sensitive pattern in distribution: {name}")
        if "/endpoints/" in name and name.endswith(".json"):
            endpoint = json.loads(content)
            if {"source", "fixture", "contract_fixture", "tests"} & endpoint.keys():
                raise ValueError(f"Private endpoint field in distribution: {name}")
            endpoints += 1
    if endpoints != 406:
        raise ValueError(f"Expected 406 public endpoints, found {endpoints} in {path}")
    return endpoints


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.archives:
        print(f"{path}: {check(path)} public endpoints")


if __name__ == "__main__":
    main()
