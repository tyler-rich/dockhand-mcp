# SPDX-License-Identifier: Apache-2.0
"""The authenticated MCP caller.

v1 has exactly one principal per server instance; the type is the seam for multi-token and
OAuth principals later (plan §6).
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Typing only: importing the registry at runtime would load every tool module, and some of
    # them depend on this one.
    from dockhand_mcp.tools.registry import Profile


@dataclass(frozen=True, slots=True)
class Principal:
    name: str
    profile: Profile
