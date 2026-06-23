import json
import re
import hashlib
from pydantic import BaseModel
from typing import Optional


class MCPServer(BaseModel):
    name: str
    command: Optional[str] = None
    args: list[str] = []
    env: dict[str, str] = {}
    url: Optional[str] = None
    transport: Optional[str] = None


class MCPConfig(BaseModel):
    config_hash: str
    servers: list[MCPServer]


def _strip_jsonc_comments(text: str) -> str:
    """Strip // line comments and /* */ block comments from JSONC text.

    Fully string-aware state machine: escape sequences inside strings are
    skipped as a pair so `"\\"` (escaped backslash) never incorrectly
    toggles the in-string state.
    """
    result: list[str] = []
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == '\\' and i + 1 < len(text):
                # Escaped character — consume both chars without toggling state
                result.append(ch)
                result.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            result.append(ch)
        else:
            if ch == '"':
                in_string = True
                result.append(ch)
            elif ch == '/' and i + 1 < len(text):
                if text[i + 1] == '/':
                    # Line comment — skip to end of line
                    while i < len(text) and text[i] != '\n':
                        i += 1
                    continue
                elif text[i + 1] == '*':
                    # Block comment — skip to */
                    i += 2
                    while i < len(text) - 1:
                        if text[i] == '*' and text[i + 1] == '/':
                            i += 2
                            break
                        i += 1
                    continue
                else:
                    result.append(ch)
            else:
                result.append(ch)
        i += 1
    return ''.join(result)


def _extract_first_json_object(text: str) -> str:
    """Return the first complete {...} block from text (handles multi-object JSONC files).

    String-aware: does not count { or } that appear inside quoted strings.
    """
    depth = 0
    in_string = False
    start = -1
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == '\\' and in_string:
            i += 2  # skip escaped character entirely
            continue
        if ch == '"':
            in_string = not in_string
        elif not in_string:
            if ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and start != -1:
                    return text[start:i + 1]
        i += 1
    return text[start:] if start != -1 else text


def parse_config(config_json: str) -> MCPConfig:
    # Pre-process: strip JSONC comments, then extract first JSON object
    # (some real-world files contain multiple objects or comment headers)
    preprocessed = _strip_jsonc_comments(config_json)
    preprocessed = _extract_first_json_object(preprocessed)
    try:
        data = json.loads(preprocessed)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON: {e}")

    if not isinstance(data, dict):
        raise ValueError("Config must be a JSON object")

    config_hash = hashlib.sha256(config_json.encode()).hexdigest()[:16]

    raw_servers = data.get("mcpServers", {})
    if not isinstance(raw_servers, dict):
        raise ValueError("'mcpServers' must be an object")

    servers: list[MCPServer] = []
    for name, server_data in raw_servers.items():
        if not isinstance(server_data, dict):
            continue
        servers.append(MCPServer(
            name=name,
            command=server_data.get("command"),
            args=[str(a) for a in server_data.get("args", [])],
            env={k: str(v) for k, v in server_data.get("env", {}).items()},
            url=server_data.get("url"),
            transport=server_data.get("transport"),
        ))

    return MCPConfig(config_hash=config_hash, servers=servers)
