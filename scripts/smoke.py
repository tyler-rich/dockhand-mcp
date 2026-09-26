# SPDX-License-Identifier: Apache-2.0
"""Live smoke client for a running dockhand-mcp server (maintainer tooling, not a tool).

Built on the official MCP SDK client. The bearer token is read from the file named by
DOCKHAND_MCP_TOKEN_FILE, never from argv, and never printed. Payloads are shown only with
--show, and always redacted.

    uv run python scripts/smoke.py list
    uv run python scripts/smoke.py call dockhand_health --args '{}'
    uv run python scripts/smoke.py run scripts/smoke-plans/health.json

A plan is a JSON list of steps, `{"tool": ..., "args": {...}, "expect": {...}, "save": {...}}`.
`expect` may hold `ok` (bool), `error.code`, `verified` (bool), `equals` / `not_equals`
(objects mapping a dotted path into the result envelope, e.g. `data.database.healthy`, to a
value), `each_matches` (dotted path to a list, every element of which must fully match a
regex), `includes_match` / `excludes_match` (dotted path to a list of objects, mapped to fields
that some element must / no element may have), and `any_of` (a list of expectation objects, at
least one of which must hold).

`save` stores values from a step's result for later steps: `{"name": "data.items.0.id"}`, or
`{"name": {"path": "data.items.0.id", "default": 1}}`, or picked from a list:
`{"name": {"path": "data.items", "pick": {"field": "name", "skip_prefix": "mcp-smoke-",
"probe": {"tool": ..., "args": {... "${candidate}" ...}, "expect": {...}}}}}` saves the first
item's `field` that does not start with `skip_prefix` and, with `probe`, for which that call (the
value substituted for `${candidate}`) meets its expectations. In later steps, any argument or
expected value that is exactly `"${name}"` is replaced by the saved value (any JSON type). A
step that needs a name nothing saved is skipped and reported, not failed. `includes` maps a
dotted path to a value its list must contain. The exit status is non-zero if any expectation
fails or any call cannot be made.

Write plans. `${test_env}` (DOCKHAND_MCP_TEST_ENVIRONMENT_ID), `${smoke_stack}` (`mcp-smoke-`
plus a random suffix) and `${smoke_container}` (that stack's `web` service container) are
pre-set. A plan that uses any of them, or calls a destructive tool, is a write plan: it is
refused before any call unless DOCKHAND_MCP_TEST_ENVIRONMENT_ID is set, every `environment_id`
in it is `${test_env}`, every `stack`/`name` is `${smoke_stack}`, every `ref` is
`${smoke_container}`, no step names any other resource, and its only destructive tools are the
ones that act on the smoke stack (`WRITE_PLAN_DESTRUCTIVE`).

    uv run python scripts/smoke.py cleanup --prefix mcp-smoke-

removes the test environment's stacks whose names start with the prefix, through the DockHand
client directly (the operator profile has no delete tool). It is maintainer tooling, not an MCP
tool: it may call only `CLEANUP_ENDPOINTS`, enforced by the client, and it refuses any prefix
other than `mcp-smoke-…` and any environment other than the test one.
"""

import argparse
import json
import os
import re
import secrets
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Final

import anyio
import httpx2
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

import dockhand_mcp.tools  # noqa: F401 - registers every tool
from dockhand_mcp.client.dockhand import DockhandClient, declared_endpoints
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.config import ConfigError, load_settings
from dockhand_mcp.guardrails.names import STACK_NAME
from dockhand_mcp.logging import redact
from dockhand_mcp.tools.registry import REGISTRY, Tier

DEFAULT_URL = "http://127.0.0.1:8080/mcp"
EXPECT_KEYS = frozenset(
    {
        "ok",
        "error.code",
        "verified",
        "equals",
        "not_equals",
        "each_matches",
        "any_of",
        "includes",
        "includes_match",
        "excludes_match",
    }
)
SMOKE_PREFIX: Final = "mcp-smoke-"
TEST_ENV_VAR: Final = "DOCKHAND_MCP_TEST_ENVIRONMENT_ID"
# Maintainer tooling, not an MCP tool: the only DockHand endpoints the cleanup routine may call,
# enforced by the client's declared-endpoint check (never a bypass or a global allow).
CLEANUP_ENDPOINTS: Final = frozenset({("GET", "/api/stacks"), ("DELETE", "/api/stacks/{name}")})
MAINTAINER_TOOLING: Final = {"smoke-cleanup": CLEANUP_ENDPOINTS}
# In a write plan these arguments may only hold the pre-set values.
WRITE_PLAN_PINNED: Final = {
    "environment_id": "${test_env}",
    "stack": "${smoke_stack}",
    "name": "${smoke_stack}",
    "ref": "${smoke_container}",
}
# ... and these, which would point a write at something else, may not appear at all.
WRITE_PLAN_FORBIDDEN: Final = frozenset(
    {
        "refs",
        "container_name",
        "image",
        "volume",
        "source",
        "new_name",
        "network",
        "git_stack_id",
        "repository_id",
        "schedule_id",
        "job_id",
    }
)
WRITE_PLAN_VARIABLES: Final = ("${test_env}", "${smoke_stack}", "${smoke_container}")
# The destructive tools a write plan may call: each acts only on the (pinned) smoke stack or its
# container. Anything else destructive (prune, image/volume/network removal, the image prune,
# clearing the activity log) could reach resources the plan did not create.
WRITE_PLAN_DESTRUCTIVE: Final = frozenset(
    {"dockhand_delete_stack", "dockhand_down_stack", "dockhand_remove_container"}
)
VARIABLE = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")
_MISSING = object()

Out = Callable[[str], None]


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="smoke.py", description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=DEFAULT_URL, help=f"MCP endpoint (default {DEFAULT_URL})")
    parser.add_argument(
        "--mode",
        default="auto",
        help="protocol negotiation: auto (default), legacy, or a revision such as 2026-07-28",
    )
    parser.add_argument("--show", action="store_true", help="print (redacted) result payloads")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list", help="list tools and their tiers")
    call = sub.add_parser("call", help="call one tool")
    call.add_argument("tool")
    call.add_argument("--args", default="{}", help="tool arguments as a JSON object")
    run = sub.add_parser("run", help="run a JSON plan of calls and expectations")
    run.add_argument("plan", type=Path)
    cleanup = sub.add_parser(
        "cleanup", help="delete the test environment's smoke stacks (DockHand client, not MCP)"
    )
    cleanup.add_argument("--prefix", required=True, help=f"stack name prefix ({SMOKE_PREFIX}…)")
    cleanup.add_argument(
        "--environment-id", type=int, help=f"must equal {TEST_ENV_VAR} (the default)"
    )
    return parser.parse_args(argv)


def load_token(env: Mapping[str, str]) -> str:
    """The MCP bearer token from DOCKHAND_MCP_TOKEN_FILE (one trailing newline stripped)."""
    path = env.get("DOCKHAND_MCP_TOKEN_FILE")
    if not path:
        raise SystemExit("smoke.py: set DOCKHAND_MCP_TOKEN_FILE to the MCP token's file")
    try:
        token = Path(path).read_text(encoding="utf-8").removesuffix("\n").removesuffix("\r")
    except OSError:
        raise SystemExit("smoke.py: cannot read DOCKHAND_MCP_TOKEN_FILE") from None
    if not token:
        raise SystemExit("smoke.py: DOCKHAND_MCP_TOKEN_FILE is empty")
    return token


def load_plan(path: Path) -> list[dict[str, Any]]:
    plan = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(plan, list) or not all(
        isinstance(step, dict) and isinstance(step.get("tool"), str) for step in plan
    ):
        raise ValueError(
            f"{path}: a plan is a JSON list of {{tool, args?, expect?, save?}} objects"
        )
    return plan


def _dotted(result: Mapping[str, Any], path: str) -> Any:
    node: Any = result
    for part in path.split("."):
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return _MISSING
    return node


def check_expectations(result: Mapping[str, Any], expect: Mapping[str, Any]) -> list[str]:
    """Failed expectations, as messages; empty when everything holds."""
    failures = [f"unknown expectation {key!r}" for key in expect if key not in EXPECT_KEYS]
    equals: dict[str, Any] = {}
    for key in ("ok", "error.code", "verified"):
        if key in expect:
            equals[key] = expect[key]
    equals.update(expect.get("equals", {}))
    for path, want in equals.items():
        got = _dotted(result, path)
        if got is _MISSING or got != want:
            shown = "missing" if got is _MISSING else json.dumps(got)
            failures.append(f"{path}: expected {json.dumps(want)}, got {shown}")
    for path, unwanted in expect.get("not_equals", {}).items():
        if _dotted(result, path) == unwanted:
            failures.append(f"{path}: expected anything but {json.dumps(unwanted)}")
    for path, pattern in expect.get("each_matches", {}).items():
        got = _dotted(result, path)
        if not isinstance(got, list):
            kind = "missing" if got is _MISSING else type(got).__name__
            failures.append(f"{path}: expected a list, got {kind}")
            continue
        bad = [
            i
            for i, item in enumerate(got)
            if not isinstance(item, str) or not re.fullmatch(pattern, item)
        ]
        if bad:
            failures.append(
                f"{path}: {len(bad)} of {len(got)} elements do not match {pattern!r} "
                f"(first at index {bad[0]})"
            )
    for path, wanted in expect.get("includes", {}).items():
        got = _dotted(result, path)
        if not isinstance(got, list) or wanted not in got:
            failures.append(f"{path}: expected a list including {json.dumps(wanted)}")
    for key, want_match in (("includes_match", True), ("excludes_match", False)):
        for path, fields in expect.get(key, {}).items():
            got = _dotted(result, path)
            if not isinstance(got, list):
                failures.append(f"{path}: expected a list")
                continue
            matched = any(
                isinstance(item, Mapping) and all(item.get(k) == v for k, v in fields.items())
                for item in got
            )
            if matched is not want_match:
                verb = "some" if want_match else "no"
                failures.append(f"{path}: expected {verb} element matching {json.dumps(fields)}")
    if "any_of" in expect:
        alternatives = [check_expectations(result, alt) for alt in expect["any_of"]]
        if alternatives and all(alternatives):
            failures.append(
                "none of any_of held: " + " | ".join("; ".join(f) for f in alternatives)
            )
    return failures


def substitute(value: Any, saved: Mapping[str, Any]) -> tuple[Any, list[str]]:
    """`value` with every exact `"${name}"` string replaced; also the names not saved."""
    if isinstance(value, str):
        m = VARIABLE.match(value)
        if m is None:
            return value, []
        return (saved[m[1]], []) if m[1] in saved else (value, [m[1]])
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        missing: list[str] = []
        for key, item in value.items():
            out[key], more = substitute(item, saved)
            missing += more
        return out, missing
    if isinstance(value, list):
        items: list[Any] = []
        missing = []
        for item in value:
            new, more = substitute(item, saved)
            items.append(new)
            missing += more
        return items, missing
    return value, []


def save_values(
    result: Mapping[str, Any], spec: Mapping[str, Any], saved: dict[str, Any]
) -> list[str]:
    """Store the values `spec` names into `saved`; returns the names that could not be found."""
    unfound = []
    for name, where in spec.items():
        path, default = (
            (where.get("path", ""), where.get("default", _MISSING))
            if isinstance(where, Mapping)
            else (where, _MISSING)
        )
        value = _dotted(result, str(path))
        if value is _MISSING:
            value = default
        if value is _MISSING:
            unfound.append(name)
        else:
            saved[name] = value
    return unfound


async def pick_value(
    client: Client, result: Mapping[str, Any], where: Mapping[str, Any], saved: Mapping[str, Any]
) -> Any:
    """The first listed value `where["pick"]` accepts (see the module docstring), or _MISSING."""
    pick = where["pick"]
    items = _dotted(result, str(where.get("path", "")))
    if not isinstance(items, list):
        return _MISSING
    field = str(pick.get("field", "name"))
    skip = pick.get("skip_prefix")
    probe = pick.get("probe")
    for item in items:
        value = item.get(field) if isinstance(item, Mapping) else None
        if not isinstance(value, str) or (isinstance(skip, str) and value.startswith(skip)):
            continue
        if probe is not None:
            args, missing = substitute(probe.get("args") or {}, {**saved, "candidate": value})
            if missing:
                return _MISSING
            probed, _ = await _call(client, str(probe["tool"]), args)
            if check_expectations(probed, probe.get("expect") or {}):
                continue
        return value
    return _MISSING


def summary_line(tool: str, result: Mapping[str, Any], seconds: float) -> str:
    """One compact line: tool, ok or error code, duration, and counts rather than values."""
    status = "ok" if result.get("ok") else f"error={_dotted(result, 'error.code')}"
    parts = [tool, status, f"{seconds * 1000:.0f}ms"]
    data = result.get("data")
    if isinstance(data, Mapping):
        parts.append(f"data_keys={len(data)}")
        items = data.get("items")
        if isinstance(items, list):
            parts.append(f"items={len(items)}")
    elif isinstance(data, list):
        parts.append(f"items={len(data)}")
    return " ".join(parts)


async def _call(client: Client, tool: str, args: Mapping[str, Any]) -> tuple[dict[str, Any], float]:
    started = time.monotonic()
    result = await client.call_tool(tool, dict(args))
    structured = result.structured_content
    if not isinstance(structured, dict):
        structured = {"ok": not result.is_error, "data": None}
    return structured, time.monotonic() - started


async def run_plan(
    client: Client,
    plan: Sequence[Mapping[str, Any]],
    *,
    show: bool = False,
    out: Out = print,
    secrets: Sequence[str] = (),
    seed: Mapping[str, Any] | None = None,
) -> int:
    failed = skipped = 0
    saved: dict[str, Any] = dict(seed or {})
    for index, step in enumerate(plan, 1):
        tool = str(step["tool"])
        args, missing = substitute(step.get("args") or {}, saved)
        expect, missing_in_expect = substitute(step.get("expect") or {}, saved)
        missing += missing_in_expect
        if missing:
            out(f"[{index}] {tool} SKIP (nothing saved for: {', '.join(sorted(set(missing)))})")
            skipped += 1
            continue
        try:
            result, seconds = await _call(client, tool, args)
        except Exception as e:
            out(f"[{index}] {tool} FAIL call raised {type(e).__name__}: {redact(str(e), secrets)}")
            failed += 1
            continue
        failures = check_expectations(result, expect)
        verdict = "PASS" if not failures else "FAIL"
        out(f"[{index}] {summary_line(tool, result, seconds)} {verdict}")
        for failure in failures:
            out(f"      {redact(failure, secrets)}")
        save = step.get("save") or {}
        picks = {k: w for k, w in save.items() if isinstance(w, Mapping) and "pick" in w}
        unfound = save_values(result, {k: w for k, w in save.items() if k not in picks}, saved)
        for name, where in picks.items():
            value = await pick_value(client, result, where, saved)
            if value is _MISSING:
                unfound.append(name)
            else:
                saved[name] = value
        if unfound:
            out(f"      nothing to save for: {', '.join(unfound)}")
        if show:
            out(redact(json.dumps(result, indent=2), secrets))
        failed += bool(failures)
    ran = len(plan) - skipped
    out(f"{ran - failed}/{ran} steps passed, {skipped} skipped")
    return 1 if failed else 0


class PlanRefusedError(ValueError):
    """A write plan that could touch something other than the test environment's smoke stack."""


def read_test_environment(env: Mapping[str, str]) -> int | None:
    """DOCKHAND_MCP_TEST_ENVIRONMENT_ID as an id, None when unset; refuses anything else."""
    raw = env.get(TEST_ENV_VAR, "").strip()
    if not raw:
        return None
    if not raw.isdigit() or int(raw) < 1:
        raise PlanRefusedError(f"{TEST_ENV_VAR} must be a positive integer")
    return int(raw)


def destructive_tools() -> frozenset[str]:
    return frozenset(t.name for t in REGISTRY.all() if t.tier is Tier.DESTRUCTIVE)


def is_write_plan(plan: Sequence[Mapping[str, Any]]) -> bool:
    text = json.dumps(plan)
    if any(variable in text for variable in WRITE_PLAN_VARIABLES):
        return True
    return any(step.get("tool") in destructive_tools() for step in plan)


def check_write_plan(plan: Sequence[Mapping[str, Any]], test_env: int | None) -> int:
    """Refuse a write plan unless it is pinned to the test environment and the smoke stack.

    Returns the test environment id.
    """
    if test_env is None:
        raise PlanRefusedError(f"this is a write plan; set {TEST_ENV_VAR} to run it")
    destructive = destructive_tools()
    for index, step in enumerate(plan, 1):
        tool = step.get("tool")
        if tool in destructive and tool not in WRITE_PLAN_DESTRUCTIVE:
            raise PlanRefusedError(f"step {index}: a write plan may not call {tool}")
        args = step.get("args") or {}
        for key, value in args.items():
            if key in WRITE_PLAN_FORBIDDEN:
                raise PlanRefusedError(f"step {index}: a write plan may not name {key!r}")
            pinned = WRITE_PLAN_PINNED.get(key)
            if pinned is not None and value != pinned:
                raise PlanRefusedError(f"step {index}: {key} must be {pinned!r}")
    return test_env


def write_plan_seed(test_env: int) -> dict[str, Any]:
    stack = SMOKE_PREFIX + secrets.token_hex(4)
    # docker compose names a service's first container <project>-<service>-1.
    return {"test_env": test_env, "smoke_stack": stack, "smoke_container": f"{stack}-web-1"}


# --- cleanup (maintainer tooling) -------------------------------------------------------------


def check_cleanup_target(name: str, environment_id: int, *, prefix: str, test_env: int) -> None:
    """Refuse anything but an `mcp-smoke-…` stack in the test environment."""
    if not prefix.startswith(SMOKE_PREFIX) or not STACK_NAME.match(prefix.rstrip("-") or "-"):
        raise PlanRefusedError(f"cleanup prefix must start with {SMOKE_PREFIX!r}")
    if environment_id != test_env:
        raise PlanRefusedError(f"cleanup runs only in {TEST_ENV_VAR} ({test_env})")
    if not name.startswith(prefix) or not STACK_NAME.match(name):
        raise PlanRefusedError(f"{name!r} does not start with {prefix!r}")


async def cleanup(
    client: DockhandClient,
    *,
    prefix: str,
    environment_id: int,
    test_env: int,
    out: Out = print,
) -> int:
    """Delete the test environment's stacks named `prefix…`; returns the exit status."""
    check_cleanup_target(prefix + "x", environment_id, prefix=prefix, test_env=test_env)
    failed = 0
    with declared_endpoints(CLEANUP_ENDPOINTS):
        body = await client.get_json("/api/stacks", params={"env": environment_id})
        names = [
            str(item["name"])
            for item in (body if isinstance(body, list) else [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ]
        targets = [n for n in names if n.startswith(prefix)]
        for name in targets:
            check_cleanup_target(name, environment_id, prefix=prefix, test_env=test_env)
            try:
                await client.delete_json(
                    "/api/stacks/{name}",
                    path_params={"name": name},
                    params={"env": environment_id, "force": True, "volumes": True, "files": True},
                )
            except DockhandError as e:
                out(f"cleanup: {name} FAILED {e.code}: {e.message}")
                failed += 1
            else:
                out(f"cleanup: {name} deleted")
    out(f"cleanup: {len(targets) - failed}/{len(targets)} stacks deleted")
    return 1 if failed else 0


async def run_cleanup(args: argparse.Namespace) -> int:
    test_env = read_test_environment(os.environ)
    if test_env is None:
        raise PlanRefusedError(f"cleanup needs {TEST_ENV_VAR}")
    environment_id = args.environment_id if args.environment_id is not None else test_env
    client = DockhandClient.from_settings(load_settings())
    try:
        return await cleanup(
            client, prefix=args.prefix, environment_id=environment_id, test_env=test_env
        )
    finally:
        await client.aclose()


async def list_tools(client: Client, *, out: Out = print) -> int:
    for tool in (await client.list_tools()).tools:
        hints = tool.annotations
        if hints is not None and hints.read_only_hint:
            tier = "read"
        elif hints is not None and hints.destructive_hint:
            tier = "destructive"
        else:
            tier = "operator"
        out(f"{tool.name}\t{tier}")
    return 0


async def main_async(
    args: argparse.Namespace, token: str, plan: list[dict[str, Any]] | None, seed: dict[str, Any]
) -> int:
    http = httpx2.AsyncClient(headers={"authorization": f"Bearer {token}"}, timeout=330.0)
    transport = streamable_http_client(args.url, http_client=http)
    async with http, Client(transport, mode=args.mode) as client:  # type: ignore[arg-type]
        if args.command == "list":
            return await list_tools(client)
        if args.command == "call":
            call_args = json.loads(args.args)
            if not isinstance(call_args, dict):
                raise SystemExit("smoke.py: --args must be a JSON object")
            step = {"tool": args.tool, "args": call_args}
            return await run_plan(client, [step], show=args.show, secrets=[token])
        return await run_plan(client, plan or [], show=args.show, secrets=[token], seed=seed)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "cleanup":
            return anyio.run(run_cleanup, args)
        plan = load_plan(args.plan) if args.command == "run" else None
        seed: dict[str, Any] = {}
        if plan is not None and is_write_plan(plan):
            seed = write_plan_seed(check_write_plan(plan, read_test_environment(os.environ)))
            test_env = seed["test_env"]
            print(f"write plan: environment {test_env}, stack {seed['smoke_stack']}")
    except (PlanRefusedError, ConfigError) as e:
        print(f"smoke.py: refused: {e}", file=sys.stderr)
        return 2
    token = load_token(os.environ)
    try:
        return anyio.run(main_async, args, token, plan, seed)
    except (OSError, httpx2.HTTPError) as e:
        print(f"smoke.py: cannot reach {args.url}: {type(e).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
