"""Safe Rich text construction for untrusted forensic and tool output."""

from __future__ import annotations

from rich.text import Text


def safe_text(value: object, *, style: str | None = None) -> Text:
    safe = "".join(
        "?"
        if (ord(char) < 32 and char not in "\n\r\t") or 127 <= ord(char) <= 159
        else char
        for char in str(value)
    )
    return Text(safe, style=style)
