# SPDX-License-Identifier: Apache-2.0
"""The container this server runs in, if any, so a tool can refuse to schedule its stop (#19).

Docker and Podman bind-mount a per-container `hostname` file, kept under the runtime's
`…/containers/<64-hex id>/…` directory, onto `/etc/hostname`. The process's own mount table
(`/proc/self/mountinfo`) therefore names the container id: only the mount whose mount point is
`/etc/hostname` counts, because on a Docker host the host's own table lists every container's
`…/containers/<id>/mounts/shm`. When the table names none, a hostname of exactly 12 hex
characters (Docker's default, the id's first 12) is taken as the short id.

When neither names an id, the protection cannot apply. `identify` also says whether this
process appears to run in a container at all (a mount on `/etc/hostname`, or the runtime's marker
file `/.dockerenv` or `/run/.containerenv`), so `dockhand-mcp check` and `serve` can report it
(`startup.py`) instead of the protection lapsing silently.

Nothing here touches the Docker socket, a host path or a subprocess (D-003): it reads this
process's own mount table, size-capped, its hostname and whether the two marker files exist.
Outside a container all of them give nothing.
"""

import functools
import re
import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Final

MOUNTINFO: Final = Path("/proc/self/mountinfo")
MAX_MOUNTINFO_BYTES: Final = 1024 * 1024
HOSTNAME_MOUNT: Final = "/etc/hostname"
CONTAINER_MARKERS: Final = (Path("/.dockerenv"), Path("/run/.containerenv"))
# The id directory in the mount's root (field 4): `…/containers/<id>/hostname` (Docker, rootless
# Docker) or `…/overlay-containers/<id>/userdata/hostname` (Podman).
_ID_IN_ROOT: Final = re.compile(r"/(?:overlay-)?containers/([0-9a-f]{64})/")
_SHORT_ID: Final = re.compile(r"^[0-9a-f]{12}$")
MIN_ID_CHARS: Final = 12


def _mount_points(mountinfo: str | None) -> list[tuple[str, str]]:
    """(root, mount point) of each mount table line."""
    out = []
    for line in (mountinfo or "").splitlines():
        fields = line.split(" ")
        if len(fields) >= 5:
            out.append((fields[3], fields[4]))
    return out


def discover(mountinfo: str | None, hostname: str) -> frozenset[str]:
    """This container's id(s) from the mount table text and the hostname; empty when none."""
    ids: set[str] = set()
    for root, point in _mount_points(mountinfo):
        found = _ID_IN_ROOT.search(root) if point == HOSTNAME_MOUNT else None
        if found:
            ids.add(found.group(1))
    if not ids and _SHORT_ID.match(hostname):
        ids.add(hostname)
    return frozenset(ids)


def _read_mountinfo() -> str | None:
    try:
        with MOUNTINFO.open("rb") as f:
            return f.read(MAX_MOUNTINFO_BYTES).decode("utf-8", "replace")
    except OSError:
        return None


def in_container(mountinfo: str | None, *, markers: bool) -> bool:
    """Whether this process appears to run in a container: a runtime marker file, or a mount on
    `/etc/hostname` (container runtimes bind-mount one; a host's own table has none)."""
    return markers or any(point == HOSTNAME_MOUNT for _, point in _mount_points(mountinfo))


@dataclass(frozen=True)
class Identity:
    ids: frozenset[str]
    in_container: bool


@functools.cache
def identify() -> Identity:
    """This server's container id(s), and whether it appears to be in a container; read once."""
    mountinfo = _read_mountinfo()
    markers = any(marker.exists() for marker in CONTAINER_MARKERS)
    return Identity(
        ids=discover(mountinfo, socket.gethostname()),
        in_container=in_container(mountinfo, markers=markers),
    )


def own_container_ids() -> frozenset[str]:
    """This server's container id(s); empty when they cannot be found."""
    return identify().ids


def matches(container_id: str, own: frozenset[str]) -> bool:
    """Whether `container_id` (full or short) is one of `own`, by prefix in either direction."""
    if len(container_id) < MIN_ID_CHARS:
        return False
    return any(
        len(mine) >= MIN_ID_CHARS
        and (container_id.startswith(mine) or mine.startswith(container_id))
        for mine in own
    )
