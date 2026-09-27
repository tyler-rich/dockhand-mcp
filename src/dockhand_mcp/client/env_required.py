# SPDX-License-Identifier: Apache-2.0
"""Operations whose environment query parameter DockHand requires (API v1.0.49).

Generated from the `/api/docs` OpenAPI document by `scripts/gen-endpoint-map.py --env-required`;
do not edit. `client/dockhand.py` refuses a request to any of these, before sending it, when the
parameter is missing or empty (#5).
"""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

# (METHOD, path template) -> the name of the required query parameter.
ENV_REQUIRED: Final[Mapping[tuple[str, str], str]] = MappingProxyType(
    {
        ("POST", "/api/containers/batch-update"): "env",
        ("POST", "/api/containers/batch-update-stream"): "env",
        ("GET", "/api/containers/check-updates"): "env",
        ("POST", "/api/containers/check-updates"): "env",
        ("DELETE", "/api/containers/pending-updates"): "env",
        ("GET", "/api/containers/pending-updates"): "env",
        ("GET", "/api/containers/sizes"): "env",
        ("GET", "/api/containers/stats"): "env",
        ("DELETE", "/api/containers/{id}"): "env",
        ("GET", "/api/containers/{id}"): "env",
        ("GET", "/api/containers/{id}/compose"): "env",
        ("POST", "/api/containers/{id}/exec"): "envId",
        ("POST", "/api/containers/{id}/exec/run"): "envId",
        ("GET", "/api/containers/{id}/files"): "env",
        ("POST", "/api/containers/{id}/files/chmod"): "env",
        ("POST", "/api/containers/{id}/files/chown"): "env",
        ("GET", "/api/containers/{id}/files/content"): "env",
        ("PUT", "/api/containers/{id}/files/content"): "env",
        ("POST", "/api/containers/{id}/files/create"): "env",
        ("DELETE", "/api/containers/{id}/files/delete"): "env",
        ("GET", "/api/containers/{id}/files/download"): "env",
        ("POST", "/api/containers/{id}/files/rename"): "env",
        ("POST", "/api/containers/{id}/files/upload"): "env",
        ("GET", "/api/containers/{id}/inspect"): "env",
        ("GET", "/api/containers/{id}/logs"): "env",
        ("GET", "/api/containers/{id}/logs/stream"): "env",
        ("POST", "/api/containers/{id}/pause"): "env",
        ("POST", "/api/containers/{id}/rename"): "env",
        ("POST", "/api/containers/{id}/restart"): "env",
        ("GET", "/api/containers/{id}/shells"): "env",
        ("POST", "/api/containers/{id}/start"): "env",
        ("GET", "/api/containers/{id}/stats"): "env",
        ("POST", "/api/containers/{id}/stop"): "env",
        ("GET", "/api/containers/{id}/top"): "env",
        ("POST", "/api/containers/{id}/unpause"): "env",
        ("POST", "/api/containers/{id}/update"): "env",
        ("GET", "/api/containers/{id}/version-notes"): "env",
        ("GET", "/api/preferences/favorite-groups"): "env",
        ("GET", "/api/preferences/favorites"): "env",
        ("GET", "/api/system/disk"): "env",
    }
)
