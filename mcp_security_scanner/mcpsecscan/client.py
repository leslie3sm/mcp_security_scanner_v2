from __future__ import annotations
import asyncio, json, os, shlex
from typing import Any
import httpx
from .models import ScanTarget, ToolInfo

INIT_PARAMS = {
    "protocolVersion": "2025-06-18",
    "capabilities": {},
    "clientInfo": {"name": "mcpsecscan", "version": "0.1.0"},
}

class MCPClientError(RuntimeError):
    pass

class JsonRpc:
    def __init__(self) -> None:
        self.next_id = 1
    def req(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        rid = self.next_id
        self.next_id += 1
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": rid, "method": method}
        if params is not None:
            msg["params"] = params
        return msg

async def scan_stdio(target: ScanTarget, timeout: float = 10.0) -> tuple[dict[str, Any], list[ToolInfo]]:
    if not target.command:
        raise MCPClientError("stdio target requires command")
    rpc = JsonRpc()
    env = {**os.environ, **target.env}
    proc = await asyncio.create_subprocess_exec(
        *shlex.split(target.command),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    try:
        init = await _stdio_request(proc, rpc.req("initialize", INIT_PARAMS), timeout)
        await _stdio_notify(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools_resp = await _stdio_request(proc, rpc.req("tools/list", {}), timeout)
        tools = _parse_tools(tools_resp.get("result", {}).get("tools", []))
        return init.get("result", {}), tools
    finally:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=2)
        except asyncio.TimeoutError:
            proc.kill()

async def _stdio_notify(proc: asyncio.subprocess.Process, msg: dict[str, Any]) -> None:
    assert proc.stdin
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()

async def _stdio_request(proc: asyncio.subprocess.Process, msg: dict[str, Any], timeout: float) -> dict[str, Any]:
    assert proc.stdin and proc.stdout
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    await proc.stdin.drain()
    line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
    if not line:
        stderr = b""
        if proc.stderr:
            try:
                stderr = await asyncio.wait_for(proc.stderr.read(2048), timeout=0.2)
            except Exception:
                pass
        raise MCPClientError(f"No MCP response. stderr={stderr.decode(errors='ignore')}")
    resp = json.loads(line.decode())
    if "error" in resp:
        raise MCPClientError(str(resp["error"]))
    return resp

async def scan_http(target: ScanTarget, timeout: float = 10.0) -> tuple[dict[str, Any], list[ToolInfo], dict[str, Any]]:
    if not target.url:
        raise MCPClientError("http target requires url")
    rpc = JsonRpc()
    headers = {**target.headers, "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if target.bearer:
        headers["Authorization"] = f"Bearer {target.bearer}"
    observations: dict[str, Any] = {}
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        unauth = await client.post(target.url, json=rpc.req("initialize", INIT_PARAMS), headers={k:v for k,v in headers.items() if k.lower() != "authorization"})
        observations["unauth_status_code"] = unauth.status_code
        observations["unauth_www_authenticate"] = unauth.headers.get("www-authenticate")
        resp = await client.post(target.url, json=rpc.req("initialize", INIT_PARAMS), headers=headers)
        observations["status_code"] = resp.status_code
        observations["content_type"] = resp.headers.get("content-type")
        observations["server_header"] = resp.headers.get("server")
        data = _decode_http_mcp(resp)
        if "error" in data:
            raise MCPClientError(str(data["error"]))
        await client.post(target.url, json={"jsonrpc":"2.0","method":"notifications/initialized"}, headers=headers)
        tools_resp = await client.post(target.url, json=rpc.req("tools/list", {}), headers=headers)
        tools_data = _decode_http_mcp(tools_resp)
        return data.get("result", {}), _parse_tools(tools_data.get("result", {}).get("tools", [])), observations

def _decode_http_mcp(resp: httpx.Response) -> dict[str, Any]:
    text = resp.text.strip()
    if not text:
        return {}
    if text.startswith("event:") or "\ndata:" in text:
        for line in text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
    return resp.json()

def _parse_tools(raw_tools: list[dict[str, Any]]) -> list[ToolInfo]:
    tools = []
    for t in raw_tools:
        tools.append(ToolInfo(
            name=str(t.get("name", "")),
            description=t.get("description"),
            input_schema=t.get("inputSchema") or t.get("input_schema") or {},
        ))
    return tools
