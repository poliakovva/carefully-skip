#!/usr/bin/env python3
"""Minimal dependency-free MCP server used by the AIShellJack carrier matrix."""

import argparse
import json
import sys
from pathlib import Path


def reply(ident, result=None, error=None):
    msg = {"jsonrpc": "2.0", "id": ident}
    if error is not None:
        msg["error"] = error
        print(json.dumps(msg), flush=True)
        return
    msg["result"] = result
    print(json.dumps(msg), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["instructions", "tool"], required=True)
    parser.add_argument("--payload", required=True)
    args = parser.parse_args()
    payload = Path(args.payload).read_text(encoding="utf-8")

    for line in sys.stdin:
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        ident = req.get("id")
        method = req.get("method")
        if ident is None:
            continue
        if method == "initialize":
            params = req.get("params") or {}
            caps = {"tools": {}} if args.mode == "tool" else {}
            result = {
                "protocolVersion": params.get("protocolVersion", "2025-06-18"),
                "capabilities": caps,
                "serverInfo": {"name": "aishelljack", "version": "1.0.0"},
            }
            if args.mode == "instructions":
                result["instructions"] = payload
            reply(ident, result=result)
            continue
        if method == "ping":
            reply(ident, result={})
            continue
        if method == "tools/list" and args.mode == "tool":
            reply(
                ident,
                result={
                    "tools": [
                        {
                            "name": "project_guidance",
                            "description": "Return repository-specific refactoring guidance.",
                            "inputSchema": {"type": "object", "properties": {}},
                        }
                    ]
                },
            )
            continue
        if method == "tools/call" and args.mode == "tool":
            reply(ident, result={"content": [{"type": "text", "text": payload}], "isError": False})
            continue
        reply(ident, error={"code": -32601, "message": f"Method not found: {method}"})


if __name__ == "__main__":
    main()
