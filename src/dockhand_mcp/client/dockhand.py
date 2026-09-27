# SPDX-License-Identifier: Apache-2.0
"""The one HTTP client this server has: DockHand's REST API at DOCKHAND_URL (S-04).

- `Authorization: Bearer dh_…` only when a token is configured; `Accept: application/json` by
  default.
- Redirects are never followed: any 3xx is an `unexpected_redirect` error.
- TLS verification is on unless DOCKHAND_TLS_INSECURE; DOCKHAND_CA_BUNDLE adds a private CA.
  Environment proxy and netrc settings are ignored, so requests go only to DOCKHAND_URL.
- A request to an operation whose environment parameter the spec requires (`client/env_required.py`,
  generated from the spec) is refused, before it is sent, when that parameter is missing or empty
  (#5): DockHand answers some such requests with a 500 and others with an empty list.
- GETs are retried on unreachable/5xx (3 attempts, jittered exponential backoff); nothing else is
  retried, and 401/403 never are.
- One log line per call: method, path with query values stripped, status, milliseconds. Never
  headers or bodies.
- DockHand's answers to non-GET requests, and every error body, pass the call's output redaction
  (`client/redaction.py`) before a caller sees them. GET answers are returned as sent: tools
  read them for names, variables, read-back and job status, and their free text is redacted
  where results leave the server.

Callers name endpoints by their spec path template plus path parameters, so every call can be
checked against the calling tool's declared endpoints and recorded by tests.
"""

import logging
import random
import re
import ssl
import time
from collections.abc import (
    AsyncGenerator,
    AsyncIterator,
    Awaitable,
    Callable,
    Collection,
    Iterator,
    Mapping,
)
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import quote, urlsplit

import anyio
import httpx

from dockhand_mcp import __version__
from dockhand_mcp.client import errors
from dockhand_mcp.client.env_required import ENV_REQUIRED
from dockhand_mcp.client.errors import DockhandError
from dockhand_mcp.client.redaction import current_redactor

if TYPE_CHECKING:
    from dockhand_mcp.config import Settings

log = logging.getLogger(__name__)

Endpoint = tuple[str, str]
Recorder = Callable[[Endpoint], None]
Sleep = Callable[[float], Awaitable[None]]
Params = Mapping[str, str | int | float | bool | None]

DEFAULT_TIMEOUT: Final = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
RETRY_ATTEMPTS: Final = 3
BACKOFF_S: Final = 0.5
MAX_ERROR_BODY_READ: Final = 16 * 1024
# One SSE event's data, accumulated over its `data:` lines; the rest is dropped (S1 follow-up).
MAX_SSE_EVENT_CHARS: Final = 1024 * 1024
SSE_TRUNCATED: Final = "…[truncated]"
# The event `stream_sse` yields, with the body, when DockHand answers an SSE request with JSON
# (live DockHand 1.0.46 answers its streaming endpoints with a `{jobId}`). A NUL keeps it apart
# from any event name a stream can carry.
JSON_BODY_EVENT: Final = "\x00json-body"

_PLACEHOLDER: Final = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


class UndeclaredEndpointError(RuntimeError):
    """A tool tried to call an endpoint it did not declare at registration. A bug, not input."""


class MissingEnvironmentError(DockhandError):
    """A request to an env-required operation without its environment parameter; never sent."""

    def __init__(self, method: str, template: str, param: str) -> None:
        super().__init__(
            None,
            "validation_error",
            f"{method} {template} requires the {param} query parameter; the request was not sent",
        )


# The endpoints the running tool declared; None outside a tool (internal checks, tests).
_declared: ContextVar[frozenset[Endpoint] | None] = ContextVar("declared_endpoints", default=None)


@contextmanager
def declared_endpoints(endpoints: frozenset[Endpoint]) -> Iterator[None]:
    """Refuse, for the duration, any call to an endpoint not in `endpoints`."""
    token = _declared.set(endpoints)
    try:
        yield
    finally:
        _declared.reset(token)


# True while a destructive tool computes its preview: only GETs may be sent (D-006).
_read_only: ContextVar[bool] = ContextVar("read_only_phase", default=False)


@contextmanager
def read_only_phase() -> Iterator[None]:
    """Refuse, for the duration, any request that is not a GET, declared or not."""
    token = _read_only.set(True)
    try:
        yield
    finally:
        _read_only.reset(token)


@dataclass
class StatusBox:
    """The last HTTP status DockHand answered with inside a `track_status()` block."""

    status: int | None = None


_status: ContextVar[StatusBox | None] = ContextVar("dockhand_status", default=None)


@contextmanager
def track_status() -> Iterator[StatusBox]:
    box = StatusBox()
    token = _status.set(box)
    try:
        yield box
    finally:
        _status.reset(token)


def _fill(template: str, path_params: Mapping[str, str | int] | None) -> str:
    values = dict(path_params or {})
    names = _PLACEHOLDER.findall(template)
    missing = [n for n in names if n not in values]
    extra = sorted(set(values) - set(names))
    if missing or extra:
        raise ValueError(f"{template}: missing path parameters {missing}, unexpected {extra}")
    return _PLACEHOLDER.sub(lambda m: quote(str(values[m[1]]), safe=""), template)


def _query(params: Params | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (params or {}).items():
        if value is None:
            continue
        out[key] = str(value).lower() if isinstance(value, bool) else str(value)
    return out


def _log_path(path: str, query: Mapping[str, str]) -> str:
    return f"{path}?{'&'.join(query)}" if query else path


def _json_body(response: httpx.Response) -> Any:
    if not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        raise DockhandError(
            response.status_code,
            "dockhand_http_error",
            f"DockHand returned a non-JSON response (HTTP {response.status_code})",
            errors.body_excerpt(response.content, current_redactor()),
        ) from None


def _answer(body: Any) -> Any:
    """DockHand's answer to a write, redacted with the call's redactor.

    A top-level `jobId` is kept as sent: it is an identifier the caller polls, never output, and
    a context value must not be able to change it.
    """
    redacted = current_redactor()(body)
    if isinstance(body, dict) and isinstance(body.get("jobId"), str):
        redacted["jobId"] = body["jobId"]
    return redacted


async def _read_capped(response: httpx.Response) -> bytes:
    body = bytearray()
    async for chunk in response.aiter_bytes():
        body.extend(chunk)
        if len(body) >= MAX_ERROR_BODY_READ:
            break
    return bytes(body)


async def _sse_events(lines: AsyncIterator[str]) -> AsyncIterator[tuple[str, str]]:
    """Parse a text/event-stream into (event, data) pairs; `message` is the default event.

    An event's data is capped at MAX_SSE_EVENT_CHARS; anything beyond is replaced by one marker.
    """
    event = ""
    data: list[str] = []
    async for line in lines:
        if not line:
            if data:
                yield event or "message", "\n".join(data)
            event, data = "", []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        value = value.removeprefix(" ")
        if field == "event":
            event = value
        elif field == "data":
            size = sum(len(d) + 1 for d in data)
            if size + len(value) <= MAX_SSE_EVENT_CHARS:
                data.append(value)
            elif not data or data[-1] != SSE_TRUNCATED:
                data.append(SSE_TRUNCATED)


class DockhandClient:
    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        allow_http: bool = False,
        verify: bool | ssl.SSLContext = True,
        timeout: httpx.Timeout = DEFAULT_TIMEOUT,
        transport: httpx.AsyncBaseTransport | None = None,
        recorder: Recorder | None = None,
        retry_attempts: int = RETRY_ATTEMPTS,
        backoff_s: float = BACKOFF_S,
        sleep: Sleep = anyio.sleep,
    ) -> None:
        scheme = urlsplit(base_url).scheme
        if scheme not in ("http", "https"):
            raise ValueError("DOCKHAND_URL must be an http:// or https:// URL")
        if scheme == "http" and not allow_http:
            raise ValueError("DOCKHAND_URL uses http:// but DOCKHAND_ALLOW_HTTP is not true")
        headers = {"accept": "application/json", "user-agent": f"dockhand-mcp/{__version__}"}
        if token:
            headers["authorization"] = f"Bearer {token}"
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self._recorder = recorder
        self._attempts = retry_attempts
        self._backoff_s = backoff_s
        self._sleep = sleep
        self._http = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            verify=verify,
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        )

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        recorder: Recorder | None = None,
    ) -> DockhandClient:
        # Startup validation has already logged the DOCKHAND_TLS_INSECURE warning.
        verify: bool | ssl.SSLContext = True
        if settings.dockhand_tls_insecure:
            verify = False
        elif settings.dockhand_ca_bundle is not None:
            verify = ssl.create_default_context(cafile=str(settings.dockhand_ca_bundle))
        if settings.dockhand_url is None:
            raise ValueError("DOCKHAND_URL is required")
        token = settings.dockhand_token.get_secret_value() if settings.dockhand_token else None
        return cls(
            settings.dockhand_url,
            token=token,
            allow_http=settings.dockhand_allow_http,
            verify=verify,
            transport=transport,
            recorder=recorder,
        )

    async def aclose(self) -> None:
        await self._http.aclose()

    # --- plumbing -----------------------------------------------------------------------------

    def _admit(self, method: str, template: str, query: Mapping[str, str]) -> None:
        declared = _declared.get()
        if declared is not None and (method, template) not in declared:
            raise UndeclaredEndpointError(f"{method} {template} is not declared by this tool")
        if method != "GET" and _read_only.get():
            raise UndeclaredEndpointError(f"{method} {template} is not allowed before approval")
        param = ENV_REQUIRED.get((method, template))
        if param is not None and not query.get(param, "").strip():
            raise MissingEnvironmentError(method, template, param)
        if self._recorder is not None:
            self._recorder((method, template))

    async def _backoff(self, attempt: int) -> None:
        jitter = random.uniform(0.5, 1.5)  # noqa: S311 - retry spacing, not security
        await self._sleep(self._backoff_s * 2 ** (attempt - 1) * jitter)

    def _log(
        self, method: str, path: str, query: Mapping[str, str], status: int | None, started: float
    ) -> None:
        box = _status.get()
        if box is not None and status is not None:
            box.status = status
        log.info(
            "dockhand_request",
            extra={
                "method": method,
                "path": _log_path(path, query),
                "status": status,
                "ms": round((time.monotonic() - started) * 1000, 1),
            },
        )

    async def _request(
        self,
        method: str,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        json: Any = None,
        accept: str | None = None,
        read_timeout: float | None = None,
        allow_status: Collection[int] = (),
    ) -> httpx.Response:
        path = _fill(template, path_params)
        query = _query(params)
        self._admit(method, template, query)
        attempts = self._attempts if method == "GET" else 1
        headers = {"accept": accept} if accept else None
        request_timeout = (
            httpx.Timeout(read_timeout, connect=10.0)
            if read_timeout is not None
            else httpx.USE_CLIENT_DEFAULT
        )
        started = time.monotonic()
        status: int | None = None
        try:
            for attempt in range(1, attempts + 1):
                retry = attempt < attempts
                try:
                    response = await self._http.request(
                        method,
                        path,
                        params=query,
                        json=json,
                        headers=headers,
                        timeout=request_timeout,
                    )
                except httpx.HTTPError as exc:
                    error = errors.from_transport(exc)
                    if retry and error.code == "dockhand_unreachable":
                        await self._backoff(attempt)
                        continue
                    raise error from None
                status = response.status_code
                if 200 <= status < 300 or status in allow_status:
                    return response
                if retry and status >= 500:
                    await self._backoff(attempt)
                    continue
                raise errors.from_response(response, response.content, current_redactor())
            raise AssertionError("unreachable")  # pragma: no cover
        finally:
            self._log(method, path, query, status, started)

    # --- public API ---------------------------------------------------------------------------

    async def get_json(
        self,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        accept: str | None = None,
        read_timeout: float | None = None,
        allow_status: Collection[int] = (),
    ) -> Any:
        """GET and parse JSON. Statuses in `allow_status` return their body instead of raising."""
        response = await self._request(
            "GET",
            template,
            path_params=path_params,
            params=params,
            accept=accept,
            read_timeout=read_timeout,
            allow_status=allow_status,
        )
        return _json_body(response)

    async def post_json(
        self,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        json: Any = None,
        accept: str | None = None,
        read_timeout: float | None = None,
    ) -> Any:
        response = await self._request(
            "POST",
            template,
            path_params=path_params,
            params=params,
            json=json,
            accept=accept,
            read_timeout=read_timeout,
        )
        return _answer(_json_body(response))

    async def put_json(
        self,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        json: Any = None,
        accept: str | None = None,
        read_timeout: float | None = None,
    ) -> Any:
        response = await self._request(
            "PUT",
            template,
            path_params=path_params,
            params=params,
            json=json,
            accept=accept,
            read_timeout=read_timeout,
        )
        return _answer(_json_body(response))

    async def delete_json(
        self,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        accept: str | None = None,
        read_timeout: float | None = None,
    ) -> Any:
        response = await self._request(
            "DELETE",
            template,
            path_params=path_params,
            params=params,
            accept=accept,
            read_timeout=read_timeout,
        )
        return _answer(_json_body(response))

    async def raw(
        self,
        method: str,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        json: Any = None,
        accept: str | None = None,
        read_timeout: float | None = None,
    ) -> httpx.Response:
        """A 2xx response with its body read, for endpoints that do not answer JSON."""
        return await self._request(
            method,
            template,
            path_params=path_params,
            params=params,
            json=json,
            accept=accept,
            read_timeout=read_timeout,
        )

    async def stream_sse(
        self,
        method: str,
        template: str,
        *,
        path_params: Mapping[str, str | int] | None = None,
        params: Params | None = None,
        json: Any = None,
        read_timeout: float | None = None,
    ) -> AsyncGenerator[tuple[str, str]]:
        """Yield `(event, data)` pairs from a text/event-stream response.

        A JSON response instead yields one `(JSON_BODY_EVENT, body)` pair. Close the iterator
        (e.g. with `contextlib.aclosing`) to close the connection early.
        """
        path = _fill(template, path_params)
        query = _query(params)
        self._admit(method, template, query)
        request = self._http.build_request(
            method,
            path,
            params=query,
            json=json,
            headers={"accept": "text/event-stream"},
            timeout=(
                httpx.Timeout(read_timeout, connect=10.0)
                if read_timeout is not None
                else httpx.USE_CLIENT_DEFAULT
            ),
        )
        started = time.monotonic()
        status: int | None = None
        try:
            try:
                response = await self._http.send(request, stream=True)
            except httpx.HTTPError as exc:
                raise errors.from_transport(exc) from None
            try:
                status = response.status_code
                if not 200 <= status < 300:
                    raise errors.from_response(
                        response, await _read_capped(response), current_redactor()
                    )
                if response.headers.get("content-type", "").startswith("application/json"):
                    body = await _read_capped(response)
                    yield JSON_BODY_EVENT, body.decode("utf-8", errors="replace")
                    return
                async for event in _sse_events(response.aiter_lines()):
                    yield event
            except httpx.HTTPError as exc:
                raise errors.from_transport(exc) from None
            finally:
                with anyio.CancelScope(shield=True):
                    await response.aclose()
        finally:
            self._log(method, path, query, status, started)

    async def probe_status(self, method: str, template: str) -> int:
        """The HTTP status of a request whose body is discarded unread (edition probe)."""
        path = _fill(template, None)
        self._admit(method, template, {})
        started = time.monotonic()
        status: int | None = None
        try:
            try:
                response = await self._http.send(
                    self._http.build_request(method, path), stream=True
                )
            except httpx.HTTPError as exc:
                raise errors.from_transport(exc) from None
            status = response.status_code
            await response.aclose()
            return status
        finally:
            self._log(method, path, {}, status, started)
