# SPDX-License-Identifier: Apache-2.0
"""Command line: `dockhand-mcp serve | check | tools` (F-13)."""

import argparse
import json
import sys
from collections.abc import Sequence

import anyio

from dockhand_mcp import __version__
from dockhand_mcp.config import ConfigError, Settings, load_settings
from dockhand_mcp.logging import configure_logging
from dockhand_mcp.tools.registry import REGISTRY

PROG = "dockhand-mcp"


def _fail(message: str) -> int:
    print(f"{PROG}: {message}", file=sys.stderr)
    return 1


def _load() -> Settings:
    settings = load_settings()
    configure_logging(settings.log_level, settings.log_format, secrets=settings.secret_values())
    return settings


def cmd_check() -> int:
    from dockhand_mcp.client.dockhand import DockhandClient
    from dockhand_mcp.startup import run_checks

    try:
        settings = load_settings()
    except ConfigError as exc:
        return _fail(f"configuration error: {exc.reason}")

    async def checks() -> tuple[dict[str, object], list[str], list[str]]:
        client = DockhandClient.from_settings(settings)
        try:
            report = await run_checks(settings, client)
        finally:
            await client.aclose()
        return report.as_dict(), report.problems, report.warnings

    dockhand, problems, warnings = anyio.run(checks)
    disabled = frozenset(settings.disable_tools)
    report = {
        "version": __version__,
        "profile": settings.profile.value,
        "tools": [t.name for t in REGISTRY.tools_for_profile(settings.profile, disabled)],
        "dockhand": dockhand,
        "problems": problems,
        "config": settings.masked(),
    }
    for warning in warnings:
        print(f"{PROG}: warning: {warning}", file=sys.stderr)
    print(json.dumps(report, indent=2))
    return 1 if problems else 0


def cmd_tools() -> int:
    print(json.dumps(REGISTRY.catalogue(), indent=2))
    return 0


def cmd_serve() -> int:
    # Imported here so `check` and `tools` don't load the HTTP stack.
    import uvicorn

    from dockhand_mcp.client.dockhand import DockhandClient
    from dockhand_mcp.startup import verify_serve_preconditions

    try:
        settings = _load()
    except ConfigError as exc:
        return _fail(f"configuration error: {exc.reason}")

    if settings.transport == "stdio" and settings.auth_mode != "none":
        # stdio has no HTTP headers to carry a bearer token: the client is the parent process.
        return _fail("DOCKHAND_MCP_TRANSPORT=stdio requires DOCKHAND_MCP_AUTH_MODE=none")

    async def preconditions() -> None:
        client = DockhandClient.from_settings(settings)
        try:
            await verify_serve_preconditions(settings, client)
        finally:
            await client.aclose()

    try:
        anyio.run(preconditions)
    except ConfigError as exc:
        return _fail(exc.reason)

    if settings.transport == "stdio":
        return _serve_stdio(settings)

    from dockhand_mcp.transport.app import StartupError, create_app

    try:
        app = create_app(settings)
    except StartupError as exc:
        return _fail(str(exc))
    uvicorn.run(
        app,
        host=settings.bind,
        port=settings.port,
        log_config=None,  # propagate to our redacting JSON handler
        server_header=False,
        proxy_headers=False,  # X-Forwarded-For handling is ours (DOCKHAND_MCP_TRUST_PROXY)
        timeout_graceful_shutdown=10,
    )
    return 0


def _serve_stdio(settings: Settings) -> int:
    from mcp.server.stdio import stdio_server

    from dockhand_mcp.auth.principal import Principal
    from dockhand_mcp.server import build_server

    server = build_server(settings, default_principal=Principal("stdio", settings.profile))

    async def run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    anyio.run(run)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog=PROG, description="Security-first MCP server for DockHand."
    )
    parser.add_argument("--version", action="version", version=f"{PROG} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve", help="run the MCP server")
    sub.add_parser(
        "check",
        help="validate configuration, check DockHand (health, auth, token, edition) and print "
        "the result with secrets masked",
    )
    sub.add_parser("tools", help="print the tool catalogue as JSON")
    args = parser.parse_args(argv)
    commands = {"serve": cmd_serve, "check": cmd_check, "tools": cmd_tools}
    return commands[args.command]()


if __name__ == "__main__":
    sys.exit(main())
