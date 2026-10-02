"""Build-input identity for the Docker-built Azure Linux guest."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .build_constants import (
    AzureLinuxBuildConstants,
    BuildConstants,
    DockerBuildConstants,
)
from .common import sha256_file


def input_files() -> tuple[Path, ...]:
    """Return the checkout files that define the Azure Linux initramfs."""
    root = BuildConstants.REPO_ROOT
    files = [root / DockerBuildConstants.DOCKERFILE]
    for directory in AzureLinuxBuildConstants.GUEST_SOURCE_DIRECTORIES:
        files.extend(path for path in (root / directory).rglob("*") if path.is_file())
    return tuple(sorted(files, key=lambda path: path.relative_to(root).as_posix()))


def input_sha256(
    *,
    image: str = AzureLinuxBuildConstants.IMAGE,
    version: str = AzureLinuxBuildConstants.VERSION,
) -> str:
    """Return the aggregate digest of the Azure Linux initramfs build inputs."""
    root = BuildConstants.REPO_ROOT
    document = {
        "domain": AzureLinuxBuildConstants.INPUT_DIGEST_DOMAIN,
        "format": AzureLinuxBuildConstants.INPUT_DIGEST_FORMAT,
        "version": version,
        "architecture": AzureLinuxBuildConstants.ARCHITECTURE,
        "image": image,
        "files": [
            {
                "path": path.relative_to(root).as_posix(),
                "sha256": sha256_file(path),
            }
            for path in input_files()
        ],
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(encoded).hexdigest()
