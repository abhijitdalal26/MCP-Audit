"""
Research Prototype: Unicode Steganography Detection for MCP Configs

Standalone module — no engine dependencies.
Integrated versions live in apps/api/engine/checks/tool_poisoning.py (PI-005)
and apps/api/engine/checks/supply_chain.py (SC-006).

See RESEARCH.md for full background, attack mechanism, and references.
"""

from __future__ import annotations
import unicodedata
from dataclasses import dataclass, field


# --- PI-005 character tables ---

# Invisible characters: render as nothing in all MCP client UIs
# but are processed by the LLM and bypass regex-based checks like PI-001.
INVISIBLE_CHARS: dict[str, str] = {
    '​': 'Zero Width Space',
    '‌': 'Zero Width Non-Joiner',
    '‍': 'Zero Width Joiner',
    '﻿': 'BOM / Zero Width No-Break Space',
    '⁠': 'Word Joiner',
    '⁡': 'Function Application (invisible)',
    '⁢': 'Invisible Times',
    '⁣': 'Invisible Separator',
    '⁤': 'Invisible Plus',
    '­': 'Soft Hyphen',
    '᠎': 'Mongolian Vowel Separator',
    '͏': 'Combining Grapheme Joiner',
}

# Bidi override characters: can reverse text direction (Trojan Source technique).
# CVE-2021-42574 showed these make text appear to say X while actually being Y.
# U+202E (RTL Override) is the most dangerous — it reverses ALL subsequent text.
BIDI_OVERRIDE_CHARS: dict[str, str] = {
    '‪': 'LTR Embedding',
    '‫': 'RTL Embedding',
    '‬': 'Pop Directional Formatting',
    '‭': 'LTR Override',
    '‮': 'RTL Override (Trojan Source — CVE-2021-42574)',
    '⁦': 'LTR Isolate',
    '⁧': 'RTL Isolate',
    '⁨': 'First Strong Isolate',
    '⁩': 'Pop Directional Isolate',
}

ALL_STEALTH_CHARS: dict[str, str] = {**INVISIBLE_CHARS, **BIDI_OVERRIDE_CHARS}


@dataclass
class StealthCharHit:
    """One invisible/bidi character found in a scanned string."""
    position: int
    char: str
    codepoint: str         # "U+200B"
    name: str              # "Zero Width Space"
    is_bidi: bool
    source_field: str      # "args", "env", "package", "server_name"
    source_key: str        # which arg index or env key


@dataclass
class ScanResult:
    """Result of scanning one MCP server config dict."""
    server_name: str
    pi005_hits: list[StealthCharHit] = field(default_factory=list)
    sc006_hits: list[StealthCharHit] = field(default_factory=list)

    @property
    def has_bidi(self) -> bool:
        return any(h.is_bidi for h in self.pi005_hits)

    @property
    def is_clean(self) -> bool:
        return not self.pi005_hits and not self.sc006_hits


def scan_text(text: str, source_field: str, source_key: str) -> list[StealthCharHit]:
    """Scan a string for invisible and bidi override Unicode characters (PI-005)."""
    hits: list[StealthCharHit] = []
    seen: set[str] = set()
    for i, char in enumerate(text):
        if char in ALL_STEALTH_CHARS and char not in seen:
            seen.add(char)
            hits.append(StealthCharHit(
                position=i,
                char=char,
                codepoint=f'U+{ord(char):04X}',
                name=ALL_STEALTH_CHARS[char],
                is_bidi=char in BIDI_OVERRIDE_CHARS,
                source_field=source_field,
                source_key=source_key,
            ))
    return hits


def scan_package_name(package: str) -> list[StealthCharHit]:
    """
    Scan a package name (from npm/uvx args) for non-ASCII characters (SC-006).

    npm package names are restricted to ASCII [a-z0-9_.\-@/].
    PyPI names are restricted to [A-Za-z0-9._-].
    Any codepoint > 127 is either a homoglyph attack or a copy-paste corruption.
    """
    hits: list[StealthCharHit] = []
    for i, char in enumerate(package):
        if ord(char) > 127:
            char_name = unicodedata.name(char, 'UNKNOWN CHARACTER')
            char_cat = unicodedata.category(char)
            hits.append(StealthCharHit(
                position=i,
                char=char,
                codepoint=f'U+{ord(char):04X}',
                name=f'{char_name} [cat:{char_cat}]',
                is_bidi=False,
                source_field='package',
                source_key=package,
            ))
    return hits


def scan_server(
    server_name: str,
    args: list[str],
    env: dict[str, str],
    package: str | None = None,
) -> ScanResult:
    """
    Full PI-005 + SC-006 scan for one MCP server config.

    Args:
        server_name: The server's JSON key name.
        args: The server's args list.
        env: The server's env dict.
        package: The extracted npm/uvx package name (optional — extracted from args if None).

    Returns:
        ScanResult with all hits.
    """
    result = ScanResult(server_name=server_name)

    # PI-005: scan args
    for i, arg in enumerate(args):
        result.pi005_hits.extend(scan_text(arg, 'args', f'args[{i}]'))

    # PI-005: scan env values (keys are usually ASCII — focus on values)
    for key, value in env.items():
        result.pi005_hits.extend(scan_text(value, 'env', key))

    # PI-005: scan server name too (catches case where name itself has invisible chars)
    result.pi005_hits.extend(scan_text(server_name, 'server_name', 'name'))

    # SC-006: scan package name
    if package is None:
        package = _extract_package(args)
    if package:
        result.sc006_hits.extend(scan_package_name(package))

    return result


def _extract_package(args: list[str]) -> str | None:
    """Extract the first non-flag arg (the package name) from npx/uvx args."""
    for arg in args:
        if not arg.startswith('-'):
            return arg
    return None


def render_safe(text: str, max_len: int = 80) -> str:
    """
    Render a string safely for display, escaping non-printable and non-ASCII chars.
    Use this when including user-controlled strings in Finding.detail.
    """
    parts: list[str] = []
    for char in text[:max_len]:
        if char in ALL_STEALTH_CHARS or ord(char) > 127 or ord(char) < 32:
            parts.append(f'\\u{ord(char):04X}')
        else:
            parts.append(char)
    if len(text) > max_len:
        parts.append('...')
    return ''.join(parts)


def summarize_hits(hits: list[StealthCharHit]) -> str:
    """Human-readable summary of detected characters, for use in Finding.title."""
    names = list({h.name for h in hits})
    if len(names) <= 2:
        return ', '.join(names)
    return f'{names[0]}, {names[1]} (+{len(names) - 2} more)'
