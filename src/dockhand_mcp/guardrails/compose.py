# SPDX-License-Identifier: Apache-2.0
"""Compose guardrails (docs/SECURITY.md §5): findings about a compose document, never a verdict.

The document is parsed with `yaml.safe_load`, which also resolves anchors, aliases and `<<:`
merge keys, so a setting hidden behind an `x-` anchor is checked where it lands. Values are then
interpolated the way docker compose does (`$VAR`, `${VAR}`, `${VAR:-d}`, `${VAR-d}`,
`${VAR:?e}`, `${VAR?e}`, `${VAR:+r}`, `${VAR+r}`, `$$`) with the stack's real variables, and the
checks run on the result. A variable whose value DockHand masks (`***`) cannot be seen: using it
where a check needs its value is an error.

Bind sources are judged lexically: quotes stripped, `..` resolved, trailing `/` dropped. Host-side
symlinks cannot be resolved from here. A source equal to, a parent of, or inside a denied path is
an error; five read-only system paths are the only exceptions, and DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND
can lift only the configurable denials (`/root`, `/var/lib/containerd`).

Findings carry rule, severity, service, location and message; messages name variables and show
resolved bind paths, never other environment values. Callers decide: `strict` refuses on any
error finding, `warn` refuses nothing.
"""

import posixpath
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Literal

import yaml

from dockhand_mcp.client.errors import DockhandError

MAX_COMPOSE_BYTES: Final = 512 * 1024
MAX_NODES: Final = 200_000
MAX_DEPTH: Final = 64

# SECURITY §5: denied bind sources no DOCKHAND_MCP_GUARDRAIL_ALLOW_BIND entry may ever cover.
NON_CONFIGURABLE_DENY: Final = (
    "/",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/boot",
    "/var/lib/docker",
    "/var/run/docker.sock",
    "/run/docker.sock",
)
# Denied unless an allow-list entry covers the source.
CONFIGURABLE_DENY: Final = ("/root", "/var/lib/containerd")
# Allowed only as these exact (normalised) sources, and only when mounted read-only.
READ_ONLY_EXCEPTIONS: Final = frozenset(
    {
        "/etc/localtime",
        "/etc/timezone",
        "/etc/ssl/certs",
        "/etc/ca-certificates",
        "/etc/pki/ca-trust/extracted",
    }
)

DANGEROUS_CAPS: Final = frozenset({"ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE"})
WARNING_CAPS: Final = frozenset({"NET_ADMIN"})
HOST_NAMESPACE_KEYS: Final = ("network_mode", "pid", "ipc", "userns_mode")
UNCONFINED_OPTS: Final = frozenset({"seccomp", "apparmor"})
DB_PORTS: Final = frozenset({5432, 3306, 6379, 27017, 9200})
LOOPBACK_IPS: Final = frozenset({"127.0.0.1", "::1", "localhost"})
TRUTHY: Final = frozenset({"true", "1", "yes", "y", "on"})
CREDENTIAL_WORDS: Final = ("PASSWORD", "SECRET", "TOKEN", "KEY")
SYMLINK_NOTE: Final = "judged lexically; host-side symlinks cannot be resolved from here"
_SECURITY_OPT: Final = re.compile(r"^([a-z_-]+)[:=](.*)$")

Severity = Literal["error", "warning"]
Mode = Literal["strict", "warn"]


class ComposeRejectedError(DockhandError):
    """A document the guardrails cannot evaluate: refused in every mode (fail closed)."""

    def __init__(self, message: str) -> None:
        super().__init__(None, "validation_error", message)


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    service: str | None
    path: str
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "service": self.service,
            "path": self.path,
            "message": self.message,
        }


def errors(findings: Iterable[Finding]) -> list[Finding]:
    return [f for f in findings if f.severity == "error"]


def blocks(findings: Iterable[Finding], mode: Mode) -> bool:
    """Whether `mode` refuses a write with these findings (strict: any error; warn: never)."""
    return mode == "strict" and bool(errors(findings))


def report(findings: Sequence[Finding], mode: Mode) -> dict[str, Any]:
    """The `guardrails` section of a result."""
    return {
        "mode": mode,
        "blocked": blocks(findings, mode),
        "counts": {
            "error": len(errors(findings)),
            "warning": sum(1 for f in findings if f.severity == "warning"),
        },
        "findings": [f.as_dict() for f in findings],
    }


def new_findings(before: Iterable[Finding], after: Iterable[Finding]) -> list[Finding]:
    """Findings in `after` that `before` does not have (same rule, place and message)."""
    seen = {(f.rule, f.service, f.path, f.message) for f in before}
    return [f for f in after if (f.rule, f.service, f.path, f.message) not in seen]


# --- parsing ----------------------------------------------------------------------------------


def load_compose(text: str) -> dict[str, Any]:
    """Parse a compose document; refuse oversized, unparseable or non-mapping ones."""
    size = len(text.encode("utf-8"))
    if size > MAX_COMPOSE_BYTES:
        raise ComposeRejectedError(
            f"compose document is {size} bytes; the limit is {MAX_COMPOSE_BYTES} bytes"
        )
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        where = f" (line {mark.line + 1})" if mark is not None else ""
        raise ComposeRejectedError(f"compose document is not valid YAML{where}") from None
    if not isinstance(doc, dict):
        raise ComposeRejectedError("compose document must be a YAML mapping")
    return doc


# --- interpolation ----------------------------------------------------------------------------


class _Masked:
    def __repr__(self) -> str:
        return "MASKED"


MASKED: Final = _Masked()
"""A variable that is set but whose value DockHand masks (`***`) or never returns."""

Variables = Mapping[str, "str | _Masked"]

_NAME: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A masked value is substituted by this marker, so checks can tell where it landed.
_MARK_OPEN: Final = ""
_MARK_CLOSE: Final = ""
_MARKER: Final = re.compile(f"{_MARK_OPEN}([A-Za-z_][A-Za-z0-9_]*){_MARK_CLOSE}")


def masked_names(value: str) -> list[str]:
    """Names of masked variables substituted into `value`."""
    return _MARKER.findall(value)


def _display(value: str) -> str:
    return _MARKER.sub(lambda m: "${" + m[1] + "}", value)


@dataclass
class _Interp:
    variables: Variables | None
    required_unset: list[str] = field(default_factory=list)

    def value(self, name: str) -> str | _Masked | None:
        if self.variables is None:
            return None
        return self.variables.get(name)

    def run(self, text: str) -> str:
        out: list[str] = []
        i = 0
        while i < len(text):
            c = text[i]
            if c != "$":
                out.append(c)
                i += 1
                continue
            nxt = text[i + 1 : i + 2]
            if nxt == "$":
                out.append("$")
                i += 2
            elif nxt == "{":
                end = _closing_brace(text, i + 2)
                if end < 0:
                    out.append(text[i:])  # invalid; compose would refuse it
                    break
                out.append(self._braced(text[i + 2 : end]))
                i = end + 1
            else:
                m = _NAME.match(text, i + 1)
                if m is None:
                    out.append(c)
                    i += 1
                else:
                    out.append(self._substitute(m[0], self.value(m[0])))
                    i = m.end()
        return "".join(out)

    def _substitute(self, name: str, value: str | _Masked | None) -> str:
        if isinstance(value, _Masked):
            return f"{_MARK_OPEN}{name}{_MARK_CLOSE}"
        return value or ""

    def _braced(self, body: str) -> str:
        m = _NAME.match(body)
        if m is None:
            return "${" + body + "}"  # invalid; compose would refuse it
        name, rest = m[0], body[m.end() :]
        value = self.value(name)
        is_set = value is not None
        non_empty = isinstance(value, _Masked) or bool(value)
        if rest == "":
            return self._substitute(name, value)
        for op in (":-", "-", ":?", "?", ":+", "+"):
            if not rest.startswith(op):
                continue
            arg = rest[len(op) :]
            present = non_empty if op.startswith(":") else is_set
            if op in (":-", "-"):
                return self._substitute(name, value) if present else self.run(arg)
            if op in (":?", "?"):
                if not present:
                    self.required_unset.append(name)
                    return ""
                return self._substitute(name, value)
            return self.run(arg) if present else ""
        return "${" + body + "}"


def _closing_brace(text: str, start: int) -> int:
    depth = 1
    i = start
    while i < len(text):
        if text.startswith("${", i):
            depth += 1
            i += 2
            continue
        if text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def interpolate(text: str, variables: Variables | None) -> tuple[str, list[str]]:
    """`text` interpolated; also the names of required (`?`) variables that were unset."""
    interp = _Interp(variables)
    return interp.run(text), interp.required_unset


@dataclass
class _Walker:
    interp: _Interp
    nodes: int = 0

    def tree(self, node: Any, depth: int = 0) -> Any:
        """A copy of `node` with every string value (not key) interpolated."""
        self.nodes += 1
        if self.nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ComposeRejectedError(
                "compose document is too complex to check (anchors and aliases expand beyond "
                f"{MAX_NODES} values or {MAX_DEPTH} levels)"
            )
        if isinstance(node, str):
            return self.interp.run(node)
        if isinstance(node, dict):
            return {k: self.tree(v, depth + 1) for k, v in node.items()}
        if isinstance(node, list):
            return [self.tree(v, depth + 1) for v in node]
        return node


# --- bind sources -----------------------------------------------------------------------------


def _strip_quotes(value: str) -> str:
    value = value.strip()
    while len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1].strip()
    return value


def normalise_source(source: str) -> str:
    """A bind source with quotes stripped and `..`, `.`, `//` and trailing `/` resolved."""
    value = _strip_quotes(source)
    if not value:
        return value
    path = posixpath.normpath(value)
    if path.startswith("//"):
        path = "/" + path.lstrip("/")
    return path


def _covers(parent: str, child: str) -> bool:
    """`child` is `parent` or lies inside it."""
    return child == parent or parent == "/" or child.startswith(parent.rstrip("/") + "/")


def _denials(path: str) -> list[str]:
    """Deny entries `path` equals, is a parent of, or lies inside."""
    out = []
    for denied in (*NON_CONFIGURABLE_DENY, *CONFIGURABLE_DENY):
        if path == denied or _covers(path, denied):
            out.append(denied)
        elif denied != "/" and _covers(denied, path):
            out.append(denied)
    return out


def _is_path(source: str) -> bool:
    return source.startswith(("/", ".", "~"))


@dataclass
class _Checker:
    allow_bind: tuple[str, ...]
    findings: list[Finding] = field(default_factory=list)

    def add(self, rule: str, severity: Severity, service: str | None, path: str, msg: str) -> None:
        self.findings.append(Finding(rule, severity, service, path, msg))

    def bind_source(
        self,
        raw: str,
        source: str,
        *,
        read_only: bool,
        service: str | None,
        where: str,
        what: str = "bind mount source",
    ) -> None:
        """Check one host path. `raw` is as written, `source` after interpolation."""
        variables = sorted(set(re.findall(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)", raw)))
        via = f" (from {', '.join('${' + v + '}' for v in variables)})" if variables else ""
        hidden = masked_names(source)
        if hidden:
            names = ", ".join(sorted(set(hidden)))
            self.add(
                "bind_source_unresolvable",
                "error",
                service,
                where,
                f"{what} uses {names}, whose value DockHand masks, so the host path cannot be "
                "checked",
            )
            return
        value = _strip_quotes(source)
        if not value:
            self.add(
                "bind_source_unresolvable",
                "error",
                service,
                where,
                f"{what} is empty after variable substitution{via}",
            )
            return
        if value.startswith("~"):
            self.add(
                "bind_source_home",
                "error",
                service,
                where,
                f"{what} starts with '~'; use an absolute path or one relative to the stack",
            )
            return
        path = normalise_source(value)
        if not path.startswith("/"):
            if path == ".." or path.startswith("../"):
                self.add(
                    "bind_source_escapes_stack_dir",
                    "error",
                    service,
                    where,
                    f"{what} {path!r}{via} leaves the stack directory",
                )
            return
        denied = _denials(path)
        if not denied:
            return
        if path in READ_ONLY_EXCEPTIONS:
            if read_only:
                return
            self.add(
                "bind_mount_denied",
                "error",
                service,
                where,
                f"{what} {path!r}{via} is allowed only read-only ({SYMLINK_NOTE})",
            )
            return
        configurable_only = all(d in CONFIGURABLE_DENY for d in denied)
        if configurable_only and any(_covers(a, path) for a in self.allow_bind):
            return
        self.add(
            "bind_mount_denied",
            "error",
            service,
            where,
            f"{what} {path!r}{via} is, contains or lies inside the denied path "
            f"{denied[0]!r} ({SYMLINK_NOTE})",
        )


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return isinstance(value, str | int) and str(value).strip().lower() in TRUTHY


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return [] if value is None else [value]


def _mode_read_only(mode: str) -> bool:
    return "ro" in {o.strip() for o in mode.split(",")}


def _items(value: Any) -> Iterator[tuple[str, Any]]:
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k), v


# --- the checks -------------------------------------------------------------------------------


def _check_volumes(c: _Checker, name: str, raw_svc: dict[str, Any], svc: dict[str, Any]) -> None:
    raw_list = _as_list(raw_svc.get("volumes"))
    for i, item in enumerate(_as_list(svc.get("volumes"))):
        where = f"services.{name}.volumes[{i}]"
        raw_item = raw_list[i] if i < len(raw_list) else item
        if isinstance(item, str):
            parts = item.split(":")
            if len(parts) < 2:
                continue  # anonymous volume: a container path only
            source = _strip_quotes(parts[0])
            raw_source = raw_item.split(":")[0] if isinstance(raw_item, str) else source
            if not source and "$" not in raw_source and not masked_names(item):
                continue
            if not (_is_path(source) or masked_names(source) or not source):
                continue  # a named volume
            read_only = len(parts) > 2 and _mode_read_only(parts[2])
            c.bind_source(raw_source, source, read_only=read_only, service=name, where=where)
        elif isinstance(item, dict):
            kind = str(item.get("type", "")).strip()
            long_source = item.get("source")
            if not isinstance(long_source, str):
                continue
            if kind != "bind" and not (
                kind == "" and (_is_path(long_source) or masked_names(long_source))
            ):
                continue
            raw_long = raw_item.get("source", long_source) if isinstance(raw_item, dict) else None
            c.bind_source(
                str(raw_long if raw_long is not None else long_source),
                long_source,
                read_only=_truthy(item.get("read_only")),
                service=name,
                where=f"{where}.source",
            )


def _check_host_files(c: _Checker, name: str, raw_svc: dict[str, Any], svc: dict[str, Any]) -> None:
    raw_files = _as_list(raw_svc.get("env_file"))
    for i, item in enumerate(_as_list(svc.get("env_file"))):
        path = item.get("path") if isinstance(item, dict) else item
        raw = raw_files[i] if i < len(raw_files) else item
        raw_path = raw.get("path") if isinstance(raw, dict) else raw
        if isinstance(path, str):
            c.bind_source(
                str(raw_path),
                path,
                read_only=True,
                service=name,
                where=f"services.{name}.env_file[{i}]",
                what="env_file path",
            )


def _check_service(c: _Checker, name: str, raw_svc: dict[str, Any], svc: dict[str, Any]) -> None:
    base = f"services.{name}"

    def unresolvable(key: str, value: str) -> bool:
        hidden = masked_names(value)
        if hidden:
            c.add(
                "value_unresolvable",
                "error",
                name,
                f"{base}.{key}",
                f"{key} uses {', '.join(sorted(set(hidden)))}, whose value DockHand masks, so it "
                "cannot be checked",
            )
        return bool(hidden)

    privileged = svc.get("privileged")
    if not (isinstance(privileged, str) and unresolvable("privileged", privileged)):
        if _truthy(privileged):
            c.add("privileged", "error", name, f"{base}.privileged", "privileged: true")

    for key in HOST_NAMESPACE_KEYS:
        value = svc.get(key)
        if not isinstance(value, str) or unresolvable(key, value):
            continue
        if value.strip().lower() == "host":
            c.add("host_namespace", "error", name, f"{base}.{key}", f"{key}: host")

    for i, cap in enumerate(_as_list(svc.get("cap_add"))):
        if not isinstance(cap, str) or unresolvable(f"cap_add[{i}]", cap):
            continue
        norm = cap.strip().upper().removeprefix("CAP_")
        if norm in DANGEROUS_CAPS:
            c.add("dangerous_capability", "error", name, f"{base}.cap_add[{i}]", f"cap_add {norm}")
        elif norm in WARNING_CAPS:
            c.add(
                "dangerous_capability", "warning", name, f"{base}.cap_add[{i}]", f"cap_add {norm}"
            )

    for i, opt in enumerate(_as_list(svc.get("security_opt"))):
        if not isinstance(opt, str) or unresolvable(f"security_opt[{i}]", opt):
            continue
        # Docker accepts both `seccomp:unconfined` and `seccomp=unconfined`.
        m = _SECURITY_OPT.match(opt.replace(" ", "").lower())
        if m and m[1] in UNCONFINED_OPTS and m[2] == "unconfined":
            c.add(
                "security_opt_unconfined",
                "error",
                name,
                f"{base}.security_opt[{i}]",
                f"security_opt {m[1]}:unconfined",
            )

    if _as_list(svc.get("devices")):
        c.add("devices", "warning", name, f"{base}.devices", "host devices are mapped in")

    image = svc.get("image")
    if isinstance(image, str) and image.strip() and not masked_names(image):
        ref = image.strip()
        last = ref.rsplit("/", 1)[-1]
        shown = str(raw_svc.get("image", ref))
        if "@" not in ref:
            if ":" not in last:
                c.add("image_tag", "warning", name, f"{base}.image", f"image {shown!r} has no tag")
            elif last.rsplit(":", 1)[1] == "latest":
                c.add("image_tag", "warning", name, f"{base}.image", f"image {shown!r} is latest")

    _check_environment(c, name, raw_svc.get("environment"))
    _check_ports(c, name, svc.get("ports"))
    _check_volumes(c, name, raw_svc, svc)
    _check_host_files(c, name, raw_svc, svc)

    extends = svc.get("extends")
    if isinstance(extends, dict) and extends.get("file"):
        c.add(
            "external_content_unchecked",
            "error",
            name,
            f"{base}.extends.file",
            "extends from another file, which the guardrails cannot check",
        )
    for i, source in enumerate(_as_list(svc.get("volumes_from"))):
        if isinstance(source, str) and source.strip().startswith("container:"):
            c.add(
                "external_content_unchecked",
                "error",
                name,
                f"{base}.volumes_from[{i}]",
                "volumes_from another container, whose mounts the guardrails cannot check",
            )


def _credential_name(key: str) -> bool:
    upper = key.upper()
    return not upper.endswith("_FILE") and any(w in upper for w in CREDENTIAL_WORDS)


_REFERENCE_ONLY: Final = re.compile(r"^\$(\{[^}]*\}|[A-Za-z_][A-Za-z0-9_]*)$")


def _literal(value: Any) -> bool:
    if value is None or isinstance(value, bool):
        return False
    text = str(value).strip()
    return bool(text) and not _REFERENCE_ONLY.match(text)


def _check_environment(c: _Checker, name: str, env: Any) -> None:
    pairs: list[tuple[str, Any]] = []
    if isinstance(env, dict):
        pairs = [(str(k), v) for k, v in env.items()]
    elif isinstance(env, list):
        for item in env:
            if isinstance(item, str) and "=" in item:
                key, _, value = item.partition("=")
                pairs.append((key, value))
    for key, value in pairs:
        if _credential_name(key) and _literal(value):
            c.add(
                "literal_credential",
                "warning",
                name,
                f"services.{name}.environment.{key}",
                f"{key} is set to a literal value; prefer a variable or a DockHand secret",
            )


def _port_numbers(spec: str) -> set[int]:
    out: set[int] = set()
    for part in spec.split("-"):
        if part.isdigit():
            out.add(int(part))
    if len(out) == 2:
        low, high = min(out), max(out)
        return {p for p in DB_PORTS if low <= p <= high} | out
    return out


def _check_ports(c: _Checker, name: str, ports: Any) -> None:
    for i, port in enumerate(_as_list(ports)):
        host_ip = ""
        numbers: set[int] = set()
        if isinstance(port, int) and not isinstance(port, bool):
            numbers = {port}
        elif isinstance(port, str):
            spec = port.strip().split("/", 1)[0]
            if spec.startswith("["):
                ip, _, spec = spec[1:].partition("]")
                host_ip, spec = ip, spec.lstrip(":")
            parts = spec.rsplit(":", 2)
            if len(parts) == 3:
                host_ip = host_ip or parts[0]
            for part in parts[-2:]:
                numbers |= _port_numbers(part)
        elif isinstance(port, dict):
            host_ip = str(port.get("host_ip") or "")
            for key in ("target", "published"):
                numbers |= _port_numbers(str(port.get(key) or ""))
        if host_ip.strip("[]") in LOOPBACK_IPS:
            continue
        hit = sorted(numbers & DB_PORTS)
        if hit:
            c.add(
                "database_port_published",
                "warning",
                name,
                f"services.{name}.ports[{i}]",
                f"database port {hit[0]} is published on all interfaces",
            )


def _check_top_level(c: _Checker, raw: dict[str, Any], doc: dict[str, Any]) -> None:
    if doc.get("include"):
        c.add(
            "external_content_unchecked",
            "error",
            None,
            "include",
            "include pulls in other compose files, which the guardrails cannot check",
        )
    raw_volumes = raw.get("volumes") if isinstance(raw.get("volumes"), dict) else {}
    for vname, spec in _items(doc.get("volumes")):
        opts = spec.get("driver_opts") if isinstance(spec, dict) else None
        if not isinstance(opts, dict):
            continue
        options = {o.strip() for o in str(opts.get("o") or "").split(",")}
        device = opts.get("device")
        if "bind" not in options or not isinstance(device, str):
            continue
        raw_spec = raw_volumes.get(vname) if isinstance(raw_volumes, dict) else None
        raw_opts = raw_spec.get("driver_opts") if isinstance(raw_spec, dict) else None
        raw_device = raw_opts.get("device", device) if isinstance(raw_opts, dict) else device
        c.bind_source(
            str(raw_device),
            device,
            read_only="ro" in options,
            service=None,
            where=f"volumes.{vname}.driver_opts.device",
            what="bind-backed volume device",
        )
    for section in ("configs", "secrets"):
        raw_section = raw.get(section) if isinstance(raw.get(section), dict) else {}
        for item_name, spec in _items(doc.get(section)):
            file = spec.get("file") if isinstance(spec, dict) else None
            if not isinstance(file, str):
                continue
            raw_spec = raw_section.get(item_name) if isinstance(raw_section, dict) else None
            raw_file = raw_spec.get("file", file) if isinstance(raw_spec, dict) else file
            c.bind_source(
                str(raw_file),
                file,
                read_only=True,
                service=None,
                where=f"{section}.{item_name}.file",
                what=f"{section[:-1]} file",
            )


def check_document(
    raw: dict[str, Any],
    *,
    allow_bind: Sequence[str] = (),
    variables: Variables | None = None,
) -> list[Finding]:
    """Findings for a parsed compose document (see the module docstring)."""
    interp = _Interp(variables)
    doc = _Walker(interp).tree(raw)
    c = _Checker(tuple(allow_bind))
    raw_services = raw.get("services")
    for name, svc in _items(doc.get("services")):
        raw_svc = raw_services.get(name) if isinstance(raw_services, dict) else None
        if isinstance(svc, dict):
            _check_service(c, name, raw_svc if isinstance(raw_svc, dict) else svc, svc)
    _check_top_level(c, raw, doc)
    for var in dict.fromkeys(interp.required_unset):
        c.add(
            "variable_required_unset",
            "error",
            None,
            "variables",
            f"${{{var}}} is required (:? or ?) but not set",
        )
    return [Finding(f.rule, f.severity, f.service, f.path, _display(f.message)) for f in c.findings]


def check_compose(
    text: str,
    *,
    allow_bind: Sequence[str] = (),
    variables: Variables | None = None,
) -> list[Finding]:
    """Parse `text` and return its findings; raises `ComposeRejectedError` if it can't."""
    return check_document(load_compose(text), allow_bind=allow_bind, variables=variables)
