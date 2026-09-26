# SPDX-License-Identifier: Apache-2.0
"""Compose guardrails (docs/SECURITY.md §5): the fixture set under tests/fixtures/compose and
the bind-source, interpolation and parsing rules, checked directly on `guardrails/compose.py`.
"""

from pathlib import Path

import pytest

from dockhand_mcp.guardrails.compose import (
    MASKED,
    MAX_COMPOSE_BYTES,
    NON_CONFIGURABLE_DENY,
    READ_ONLY_EXCEPTIONS,
    ComposeRejectedError,
    Finding,
    blocks,
    check_compose,
    interpolate,
    new_findings,
    report,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "compose"


def rules(findings: list[Finding], severity: str | None = None) -> list[str]:
    return [f.rule for f in findings if severity is None or f.severity == severity]


def short(source: str, mode: str = "") -> str:
    suffix = f":{mode}" if mode else ""
    return (
        f"services:\n  web:\n    image: nginx:1.27\n    volumes:\n      - '{source}:/mnt{suffix}'\n"
    )


def long(source: str, read_only: bool = False) -> str:
    return (
        "services:\n  web:\n    image: nginx:1.27\n    volumes:\n"
        f"      - type: bind\n        source: '{source}'\n        target: /mnt\n"
        f"        read_only: {'true' if read_only else 'false'}\n"
    )


# --- the fixture set --------------------------------------------------------------------------


def test_clean_compose_has_no_findings() -> None:
    assert check_compose((FIXTURES / "clean.yaml").read_text("utf-8"), variables={}) == []


@pytest.mark.parametrize(
    ("fixture", "rule"),
    [
        ("privileged-plain", "privileged"),
        ("privileged-anchor", "privileged"),
        ("privileged-merge", "privileged"),
        ("network-host", "host_namespace"),
        ("cap-add-all", "dangerous_capability"),
        ("seccomp-unconfined", "security_opt_unconfined"),
    ],
)
def test_fixture_is_an_error(fixture: str, rule: str) -> None:
    findings = check_compose((FIXTURES / f"{fixture}.yaml").read_text("utf-8"))
    assert rules(findings, "error") == [rule]
    assert findings[0].service == "web"


# --- bind sources -----------------------------------------------------------------------------

DENIED_SOURCES = [
    *NON_CONFIGURABLE_DENY,
    "/root",
    "/var/lib/containerd",
    # trailing slashes, doubled slashes, `.` and `..` tricks, quotes
    "/etc/",
    "//etc",
    "/./proc",
    "/srv/../etc",
    "/srv/data/../../sys",
    "/var/run/../run/docker.sock",
    '"/dev"',
    # parents of a denied path
    "/var",
    "/var/lib",
    "/run",
    "/var/run",
    # inside a denied path
    "/etc/shadow",
    "/etc/sudoers",
    "/proc/1/root",
    "/dev/sda",
    "/root/.ssh",
    "/var/lib/docker/volumes/x",
    "/etc/localtime/../shadow",
    "/sys/fs/cgroup",
    "/boot/efi",
]


@pytest.mark.parametrize("source", DENIED_SOURCES)
@pytest.mark.parametrize("syntax", ["short", "long"])
def test_denied_bind_sources(source: str, syntax: str) -> None:
    text = short(source) if syntax == "short" else long(source)
    findings = check_compose(text)
    assert rules(findings, "error") == ["bind_mount_denied"], findings
    assert "symlinks cannot be resolved" in findings[0].message


@pytest.mark.parametrize("source", ["./data", "data/../conf", "/srv/media", "/opt/app/config"])
@pytest.mark.parametrize("syntax", ["short", "long"])
def test_allowed_bind_sources(source: str, syntax: str) -> None:
    text = short(source) if syntax == "short" else long(source)
    assert check_compose(text) == []


@pytest.mark.parametrize("source", sorted(READ_ONLY_EXCEPTIONS))
def test_read_only_exceptions_pass_read_only(source: str) -> None:
    assert check_compose(short(source, "ro")) == []
    assert check_compose(short(source, "ro,z")) == []
    assert check_compose(long(source, read_only=True)) == []


@pytest.mark.parametrize("source", sorted(READ_ONLY_EXCEPTIONS))
def test_read_only_exceptions_fail_read_write(source: str) -> None:
    for text in (short(source), short(source, "rw"), long(source, read_only=False)):
        findings = check_compose(text)
        assert rules(findings, "error") == ["bind_mount_denied"]
        assert "read-only" in findings[0].message


def test_exceptions_are_exact_paths() -> None:
    assert rules(check_compose(short("/etc/ssl/private", "ro"))) == ["bind_mount_denied"]
    assert rules(check_compose(short("/etc", "ro"))) == ["bind_mount_denied"]


def test_home_is_denied() -> None:
    assert rules(check_compose(short("~/data"))) == ["bind_source_home"]
    assert rules(check_compose(long("~/data"))) == ["bind_source_home"]


@pytest.mark.parametrize("source", ["../other", "../../../etc", "./a/../../b", ".."])
def test_relative_sources_may_not_leave_the_stack_dir(source: str) -> None:
    assert rules(check_compose(short(source))) == ["bind_source_escapes_stack_dir"]


def test_allow_list_lifts_configurable_denials_only() -> None:
    allow = ("/root/app", "/var/lib/containerd/snapshots")
    assert check_compose(short("/root/app/data"), allow_bind=allow) == []
    assert check_compose(short("/root/app"), allow_bind=allow) == []
    assert rules(check_compose(short("/root/.ssh"), allow_bind=allow)) == ["bind_mount_denied"]
    assert rules(check_compose(short("/root"), allow_bind=allow)) == ["bind_mount_denied"]
    # A prefix match on whole path components, not on characters.
    assert rules(check_compose(short("/root/application"), allow_bind=allow)) == [
        "bind_mount_denied"
    ]


@pytest.mark.parametrize("allowed", ["/etc", "/etc/app", "/", "/var/run/docker.sock", "/proc"])
def test_non_configurable_denials_cannot_be_allow_listed(allowed: str) -> None:
    for source in ("/etc/app/config", "/var/run/docker.sock", "/proc/1/root"):
        findings = check_compose(short(source), allow_bind=(allowed,))
        assert rules(findings) == ["bind_mount_denied"], (allowed, source)


def test_other_host_path_carriers_are_checked() -> None:
    text = (
        "services:\n"
        "  web:\n    image: nginx:1.27\n    env_file: [/etc/app.env]\n"
        "volumes:\n"
        "  hostroot:\n    driver: local\n"
        "    driver_opts: {type: none, o: bind, device: /}\n"
        "  fine:\n    driver_opts: {type: none, o: bind, device: /srv/data}\n"
        "secrets:\n  shadow: {file: /etc/shadow}\n"
        "configs:\n  tz: {file: /etc/localtime}\n"
    )
    findings = check_compose(text)
    assert sorted(f.path for f in findings) == [
        "secrets.shadow.file",
        "services.web.env_file[0]",
        "volumes.hostroot.driver_opts.device",
    ]
    assert set(rules(findings)) == {"bind_mount_denied"}


def test_content_the_guardrails_cannot_see_is_an_error() -> None:
    text = (
        "include: [../other/compose.yaml]\n"
        "services:\n"
        "  web:\n    image: nginx:1.27\n"
        "    extends: {file: ../other/compose.yaml, service: base}\n"
        "    volumes_from: ['container:portainer', 'db']\n"
        "  db:\n    image: redis:7\n    extends: {service: web}\n"
    )
    findings = check_compose(text)
    assert rules(findings, "error") == ["external_content_unchecked"] * 3
    assert sorted(f.path for f in findings) == [
        "include",
        "services.web.extends.file",
        "services.web.volumes_from[0]",
    ]


# --- other rules ------------------------------------------------------------------------------


def test_host_namespaces_capabilities_and_security_opts() -> None:
    text = (
        "services:\n  web:\n    image: nginx:1.27\n"
        "    pid: host\n    ipc: host\n    userns_mode: host\n"
        "    cap_add: [cap_sys_admin, SYS_PTRACE, SYS_MODULE, NET_ADMIN, CHOWN]\n"
        "    security_opt: ['apparmor=unconfined', 'no-new-privileges:true']\n"
    )
    findings = check_compose(text)
    assert rules(findings, "error") == [
        "host_namespace",
        "host_namespace",
        "host_namespace",
        "dangerous_capability",
        "dangerous_capability",
        "dangerous_capability",
        "security_opt_unconfined",
    ]
    assert [f.message for f in findings if f.severity == "warning"] == ["cap_add NET_ADMIN"]


def test_warnings() -> None:
    value = "hunter2-literal"
    text = (
        "services:\n"
        "  web:\n    image: nginx\n    devices: [/dev/dri]\n"
        "    ports: ['5432:5432', '127.0.0.1:6379:6379', '8080:80', {target: 27017}]\n"
        f"    environment:\n      DB_PASSWORD: {value}\n      API_KEY_FILE: /run/secrets/k\n"
        "      TOKEN: '${TOKEN}'\n"
        "  api:\n    image: 'ghcr.io/acme/api:latest'\n"
        "  pinned:\n    image: 'nginx@sha256:" + "a" * 64 + "'\n"
    )
    findings = check_compose(text)
    assert rules(findings, "error") == []
    assert sorted(rules(findings, "warning")) == sorted(
        [
            "devices",
            "image_tag",
            "image_tag",
            "literal_credential",
            "database_port_published",
            "database_port_published",
        ]
    )
    # A finding names the key, never the value.
    assert all(value not in f.message for f in findings)


# --- interpolation ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "variables", "want"),
    [
        ("${A}", {"A": "x"}, "x"),
        ("$A/b", {"A": "x"}, "x/b"),
        ("${A}", {}, ""),
        ("${A:-d}", {"A": ""}, "d"),
        ("${A-d}", {"A": ""}, ""),
        ("${A-d}", {}, "d"),
        ("${A:+r}", {"A": "x"}, "r"),
        ("${A:+r}", {"A": ""}, ""),
        ("${A+r}", {"A": ""}, "r"),
        ("${A:-${B:-z}}", {}, "z"),
        ("$$A", {"A": "x"}, "$A"),
    ],
)
def test_interpolation(text: str, variables: dict[str, str], want: str) -> None:
    assert interpolate(text, variables) == (want, [])


def test_required_variables() -> None:
    assert interpolate("${A:?need it}", {"A": ""}) == ("", ["A"])
    assert interpolate("${A?need it}", {"A": ""}) == ("", [])
    text = "services:\n  web:\n    image: 'nginx:${TAG:?set a tag}'\n"
    findings = check_compose(text, variables={})
    assert rules(findings, "error") == ["variable_required_unset"]
    assert "TAG" in findings[0].message
    assert "set a tag" not in findings[0].message
    assert check_compose(text, variables={"TAG": "1.27"}) == []


def test_default_substitution_reaches_the_bind_rules() -> None:
    findings = check_compose(short("${X:-/}"), variables={})
    assert rules(findings) == ["bind_mount_denied"]
    assert "${X}" in findings[0].message
    assert check_compose(short("${X:-/}"), variables={"X": "/srv"}) == []


def test_real_values_reach_the_bind_rules() -> None:
    assert rules(check_compose(short("${DATA_DIR}"), variables={"DATA_DIR": "/"})) == [
        "bind_mount_denied"
    ]
    assert check_compose(short("${DATA_DIR}/app"), variables={"DATA_DIR": "/srv"}) == []


def test_empty_substitution() -> None:
    # Unset → empty: `${DATA}/app` becomes /app (fine), a bare `${DATA}` leaves no source.
    assert check_compose(short("${DATA}/app"), variables={}) == []
    assert rules(check_compose(short("${DATA}"), variables={})) == ["bind_source_unresolvable"]


def test_masked_values_are_unresolvable() -> None:
    findings = check_compose(short("${DATA}/app"), variables={"DATA": MASKED})
    assert rules(findings, "error") == ["bind_source_unresolvable"]
    assert "DATA" in findings[0].message
    findings = check_compose(long("${DATA}"), variables={"DATA": MASKED})
    assert rules(findings, "error") == ["bind_source_unresolvable"]
    # A masked value anywhere a check needs it is an error too.
    text = "services:\n  web:\n    image: nginx:1.27\n    network_mode: '${NET}'\n"
    assert rules(check_compose(text, variables={"NET": MASKED})) == ["value_unresolvable"]


def test_interpolated_values_are_checked() -> None:
    text = (
        "services:\n  web:\n    image: nginx:1.27\n    privileged: '${P:-true}'\n"
        "    network_mode: '${NET:-host}'\n    cap_add: ['${CAP}']\n"
    )
    assert rules(check_compose(text, variables={"CAP": "SYS_ADMIN"})) == [
        "privileged",
        "host_namespace",
        "dangerous_capability",
    ]


# --- parsing ----------------------------------------------------------------------------------


def test_oversized_document_is_rejected() -> None:
    text = "services: {}\n# " + "x" * MAX_COMPOSE_BYTES
    with pytest.raises(ComposeRejectedError, match="limit"):
        check_compose(text)


@pytest.mark.parametrize("text", ["- a\n- b\n", "just text", "", "a: [unclosed\n"])
def test_non_mapping_or_invalid_documents_are_rejected(text: str) -> None:
    with pytest.raises(ComposeRejectedError):
        check_compose(text)


def test_alias_bombs_are_rejected() -> None:
    lines = ["a0: &a0 [x, x, x, x, x, x, x, x, x, x]"]
    for i in range(1, 9):
        refs = ", ".join([f"*a{i - 1}"] * 10)
        lines.append(f"a{i}: &a{i} [{refs}]")
    lines.append("services:\n  web:\n    image: nginx:1.27\n    command: *a8")
    with pytest.raises(ComposeRejectedError, match="too complex"):
        check_compose("\n".join(lines) + "\n")


def test_unsafe_tags_are_rejected() -> None:
    with pytest.raises(ComposeRejectedError):
        check_compose("services: !!python/object:os.system {}\n")


# --- modes ------------------------------------------------------------------------------------


def test_strict_blocks_errors_not_warnings() -> None:
    warning = Finding("devices", "warning", "web", "services.web.devices", "m")
    error = Finding("privileged", "error", "web", "services.web.privileged", "m")
    assert blocks([warning], "strict") is False
    assert blocks([warning, error], "strict") is True


def test_warn_blocks_nothing_but_reports() -> None:
    findings = check_compose((FIXTURES / "privileged-plain.yaml").read_text("utf-8"))
    assert blocks(findings, "warn") is False
    section = report(findings, "warn")
    assert section["blocked"] is False
    assert section["counts"] == {"error": 1, "warning": 0}
    assert section["findings"][0]["rule"] == "privileged"


def test_new_findings_compares_rule_place_and_message() -> None:
    before = check_compose(short("${D}"), variables={"D": "/srv"})
    after = check_compose(short("${D}"), variables={"D": "/"})
    assert rules(new_findings(before, after)) == ["bind_mount_denied"]
    assert new_findings(after, after) == []
