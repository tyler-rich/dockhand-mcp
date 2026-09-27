# SPDX-License-Identifier: Apache-2.0
"""DockHand tools, one module per domain (S1-S3b); importing this package registers them all.

`stack_files` holds the stack writes that persist content; `batch` both halves of
`POST /api/batch`; `prune` the destructive prune tool."""

from dockhand_mcp.tools import (
    activity,
    batch,
    containers,
    environments,
    git,
    health,
    images,
    jobs,
    networks,
    operations,
    prune,
    registries,
    schedules,
    settings,
    stack_files,
    stacks,
    system,
    tags,
    updates,
    volumes,
    vulnerabilities,
)

__all__ = [
    "activity",
    "batch",
    "containers",
    "environments",
    "git",
    "health",
    "images",
    "jobs",
    "networks",
    "operations",
    "prune",
    "registries",
    "schedules",
    "settings",
    "stack_files",
    "stacks",
    "system",
    "tags",
    "updates",
    "volumes",
    "vulnerabilities",
]
