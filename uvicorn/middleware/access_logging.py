"""HTTP/WebSocket access logging ASGI middleware."""

from __future__ import annotations

import http
import itertools
import logging
import time
import unicodedata
from ipaddress import IPv6Address
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from uvicorn._types import (
        ASGI3Application,
        ASGIReceiveCallable,
        ASGIReceiveEvent,
        ASGISendCallable,
        ASGISendEvent,
        Scope,
        WWWScope,
    )

logger = logging.getLogger("uvicorn.access")

# Terminal color codes
_RESET = "\033[0m"
_STATUS_INFO = "\033[32m"  # 1xx (green)
_STATUS_OK = "\033[1;92m"  # 2xx (bright green)
_STATUS_REDIRECT = "\033[32m"  # 3xx (green)
_STATUS_CLIENT_ERR = "\033[0;31m"  # 4xx (red)
_STATUS_SERVER_ERR = "\033[1;91m"  # 5xx (bold bright red)
_METHOD_READ = "\033[0;34m"  # GET, HEAD, OPTIONS (blue)
_METHOD_WRITE = "\033[1;94m"  # POST, PUT, DELETE, PATCH (bold bright blue)
_HOST = "\033[38;5;242m"  # hostname (dark grey)
_PATH = "\033[38;5;250m"  # path (white)
_TIMING = "\033[38;5;242m"  # timing/devmode (dark grey)
_WS_OPEN = "\033[38;5;226m"  # WebSocket connect (brightest yellow)
_WS_CLOSE = "\033[38;5;142m"  # WebSocket disconnect (dimmer yellow)


def _display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in ("F", "W") else 1 for char in text)


def _pad_display(text: str, width: int) -> str:
    return text + " " * max(width - _display_width(text), 0)


def _format_duration(duration: float) -> str:
    ms = int(duration * 1000)
    if ms < 2000:
        return f"{ms}ms"

    total_seconds = ms // 1000
    if total_seconds < 60:
        return f"{total_seconds}s"

    if total_seconds < 3600:
        minutes, seconds = divmod(total_seconds, 60)
        return f"{minutes}m{seconds}s"

    hours, remainder = divmod(total_seconds, 3600)
    minutes = remainder // 60
    return f"{hours}h{minutes}m"


def _status_color(status: int) -> str:
    if status < 200:
        return _STATUS_INFO
    if status < 300:
        return _STATUS_OK
    if status < 400:
        return _STATUS_REDIRECT
    if status < 500:
        return _STATUS_CLIENT_ERR
    return _STATUS_SERVER_ERR


def _method_color(method: str) -> str:
    return _METHOD_READ if method in ("GET", "HEAD", "OPTIONS") else _METHOD_WRITE


def _format_extra_timing(extra: str = "", duration: float | None = None) -> tuple[str, str]:
    timing = _format_duration(duration) if duration is not None else ""
    return (f"{extra} " if extra else "", f"{_TIMING}{timing}{_RESET}" if timing else "")


def _format_ipv6_network(ip: str) -> str:
    try:
        ip = ip.strip("[]")
        if "%" in ip:
            ip = ip.split("%")[0]
        addr = IPv6Address(ip)

        if addr.is_loopback:
            return "::1"
        if addr.is_unspecified:
            return "::"
        if addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        if addr.is_link_local:
            return str(addr)

        network_int = int(addr) >> 64
        groups: list[str] = []
        for _ in range(4):
            groups.insert(0, format(network_int & 0xFFFF, "x"))
            network_int >>= 16
        result = ":".join(groups) + "::"
        return str(IPv6Address(result + "0")).removesuffix("::")
    except ValueError:
        return ip


def _format_client_ip(ip: str) -> str:
    if not ip or ip == "-":
        return "-"
    stripped = ip.strip("[]")
    if ":" in stripped:
        return _format_ipv6_network(ip)
    return ip


def _header(scope: WWWScope, name: str) -> str | None:
    name_bytes = name.lower().encode("latin-1")
    for key, value in scope["headers"]:
        if key.lower() == name_bytes:
            return value.decode("latin-1")
    return None


def _client_host(scope: WWWScope) -> str:
    client = scope["client"]
    return client[0] if client else "-"


def _path(scope: WWWScope) -> str:
    path = scope["path"]
    query = scope["query_string"]
    if query:
        return f"{path}?{query.decode('latin-1')}"
    return path


# WebSocket connection counter (mod 100)
_ws_counter = itertools.count()


def _next_ws_id() -> str:
    return f"{next(_ws_counter) % 100:02d}"


WS_CLOSE_CODES = {
    1000: "ok",
    1001: "going away",
    1002: "protocol error",
    1003: "unsupported",
    1005: "no status",
    1006: "abnormal",
    1007: "invalid data",
    1008: "policy violation",
    1009: "too large",
    1010: "extension required",
    1011: "server error",
    1012: "restarting",
    1013: "try again",
    1014: "bad gateway",
    1015: "tls error",
}


def _http_access_log_extra(
    scope: WWWScope,
    status: int,
    duration: float,
    extra: str = "",
    method: str | None = None,
) -> dict[str, object]:
    client_addr = _client_host(scope)
    full_path = _path(scope)
    method = method if method is not None else cast(str, scope.get("method", "-"))
    method = cast(str, scope.get("state", {}).get("access_log_method") or method)

    try:
        status_phrase = http.HTTPStatus(status).phrase
    except ValueError:
        status_phrase = ""

    extra, timing = _format_extra_timing(extra, duration)

    return {
        "client": _format_client_ip(client_addr).ljust(19),
        "status": f"{_status_color(status)}{str(status).rjust(3)}{_RESET}",
        "method": (
            f"{_METHOD_READ}{_pad_display('🔌', 7)}{_RESET}"
            if method == "🔌"
            else f"{_method_color(method)}{_pad_display(method, 7)}{_RESET}"
        ),
        "host": f"{_HOST}{_header(scope, 'host') or '-'}{_RESET}",
        "path": f"{_PATH}{full_path}{_RESET}",
        "extra": extra,
        "timing": timing,
        "client_addr": client_addr,
        "status_code": f"{status} {status_phrase}",
        "request_line": f"{method} {full_path} HTTP/{scope.get('http_version', '-')}",
        "http_version": scope.get("http_version", "-"),
        "full_path": full_path,
    }


def _ws_open_extra(
    scope: WWWScope,
    ws_id: str,
    origin: str | None,
    extra: str = "",
) -> dict[str, object]:
    client_addr = _client_host(scope)
    path = scope.get("path", "")
    full_path = _path(scope)

    origin_host = origin.split("://", 1)[-1] if origin else None
    extra, timing = _format_extra_timing(extra)

    host = _header(scope, "host")
    path = f"{_PATH}{path}{_RESET}"
    if origin_host and origin_host != host:
        path += f" {_RESET}from {_HOST}{origin_host}{_RESET}"
    return {
        "client": _format_client_ip(client_addr).ljust(19),
        "status": f"{_WS_OPEN} {ws_id}{_RESET}",
        "method": f"{_METHOD_READ}{_pad_display('🔌', 7)}{_RESET}",
        "host": f"{_HOST}{host}{_RESET}" if host else "",
        "path": path,
        "extra": extra,
        "timing": timing,
        "client_addr": client_addr,
        "status_code": "",
        "request_line": f"WebSocket {path}",
        "http_version": scope.get("http_version", "-"),
        "full_path": full_path,
    }


def _ws_close_extra(
    scope: WWWScope,
    ws_id: str,
    close_code: int | None,
    duration: float,
    extra: str = "",
) -> dict[str, object]:
    client_addr = _client_host(scope)
    path = scope.get("path", "-")
    full_path = _path(scope)

    if close_code is None:
        code, status_text = "----", "unknown"
    else:
        code = str(close_code)
        status_text = WS_CLOSE_CODES.get(close_code, f"code {close_code}")

    extra, timing = _format_extra_timing(extra, duration)

    return {
        "client": " " * 19,
        "status": f"{_WS_CLOSE} {ws_id}{_RESET}",
        "method": f"{_TIMING}{_pad_display('closed', 7)}{_RESET}",
        "host": "",
        "path": f"{code} {status_text}",
        "extra": extra,
        "timing": timing,
        "client_addr": client_addr,
        "status_code": f"{code} {status_text}",
        "request_line": f"WebSocket {path}",
        "http_version": scope.get("http_version", "-"),
        "full_path": full_path,
    }


def _ws_reject_extra(
    scope: WWWScope,
    close_code: int | None,
    duration: float,
    extra: str = "",
) -> dict[str, object]:
    """Open-format line for a connection closed before accept.

    Replaces the open line (which never happened), so the client IP, host and
    path stay visible.  No connection id is printed (ids are only assigned on
    accept); the status column shows a dim ``--`` and the close reason rides
    in the extra column.
    """
    if close_code is None:
        code, status_text = "----", "unknown"
    else:
        code = str(close_code)
        status_text = WS_CLOSE_CODES.get(close_code, f"code {close_code}")

    fields = _ws_open_extra(scope, "--", _header(scope, "origin"))
    reason = f"closed {code} {status_text}"
    extra, timing = _format_extra_timing(f"{reason} {extra}" if extra else reason, duration)
    fields.update(
        {
            "status": f"{_WS_CLOSE} --{_RESET}",
            "extra": extra,
            "timing": timing,
            "status_code": f"{code} {status_text}",
        }
    )
    return fields


def _assemble_access_log(fields: dict[str, object]) -> str:
    return (
        f"{fields['client']} {fields['status']} {fields['method']}"
        f"{fields['host']}{fields['path']}{fields['extra']}{fields['timing']}"
    )


class AccessLogMiddleware:
    def __init__(self, app: ASGI3Application) -> None:
        self.app = app

    async def __call__(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        if scope["type"] == "http":
            return await self._handle_http(scope, receive, send)
        elif scope["type"] == "websocket":
            return await self._handle_websocket(scope, receive, send)
        else:
            return await self.app(scope, receive, send)

    async def _handle_http(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        start = time.perf_counter()
        www_scope = cast("WWWScope", scope)

        async def wrapped_send(message: ASGISendEvent) -> None:
            if message["type"] == "http.response.start":
                fields = _http_access_log_extra(
                    www_scope,
                    status=message["status"],
                    duration=time.perf_counter() - start,
                    extra=www_scope.get("state", {}).get("log_extra", ""),
                )
                logger.info(
                    f'{fields["client_addr"]} - "{fields["request_line"]}" {fields["status_code"]}',
                    extra=fields,
                )
            await send(message)

        return await self.app(scope, receive, wrapped_send)

    async def _handle_websocket(
        self, scope: Scope, receive: ASGIReceiveCallable, send: ASGISendCallable
    ) -> None:
        start = time.perf_counter()
        ws_id: str | None = None  # assigned on accept; rejects print "--"
        accepted = False
        closed = False

        www_scope = cast("WWWScope", scope)
        origin = _header(www_scope, "origin")

        def _extra() -> str:
            return www_scope.get("state", {}).get("log_extra", "")

        def _close_fields(message: ASGIReceiveEvent | ASGISendEvent) -> dict[str, object]:
            if accepted:
                assert ws_id is not None
                return _ws_close_extra(
                    www_scope,
                    ws_id,
                    message.get("code"),
                    time.perf_counter() - start,
                    _extra(),
                )
            return _ws_reject_extra(
                www_scope,
                message.get("code"),
                time.perf_counter() - start,
                _extra(),
            )

        async def wrapped_send(message: ASGISendEvent) -> None:
            nonlocal accepted, closed, ws_id
            if message["type"] == "websocket.accept" and not accepted:
                accepted = True
                ws_id = _next_ws_id()
                fields = _ws_open_extra(www_scope, ws_id, origin, _extra())
                logger.info(_assemble_access_log(fields), extra=fields)
            elif message["type"] == "websocket.http.response.start" and not closed:
                closed = True
                fields = _http_access_log_extra(
                    www_scope,
                    status=message["status"],
                    duration=time.perf_counter() - start,
                    extra=_extra(),
                    method="🔌",
                )
                logger.info(_assemble_access_log(fields), extra=fields)
            elif message["type"] == "websocket.close" and not closed:
                closed = True
                fields = _close_fields(message)
                logger.info(_assemble_access_log(fields), extra=fields)
            await send(message)

        async def wrapped_receive() -> ASGIReceiveEvent:
            nonlocal closed
            message = await receive()
            if message["type"] == "websocket.disconnect" and not closed:
                closed = True
                fields = _close_fields(message)
                logger.info(_assemble_access_log(fields), extra=fields)
            return message

        return await self.app(scope, wrapped_receive, wrapped_send)
