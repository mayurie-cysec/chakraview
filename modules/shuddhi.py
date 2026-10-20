"""
SHUDDHI — purification of untrusted text before it reaches an output surface.

Every string ChakraView renders that came from a third party (GitHub logins
and repo names, PTR records, ipinfo org strings, archived URLs, page titles,
service banners, resolved subdomain hosts) is attacker-influenced. Raw ANSI
escape sequences in that data let a target repaint the analyst's terminal:
clear reported leaks with \x1b[2K, reposition the cursor with \x1b[H, or
retitle the window with an OSC sequence. HTML in that data would do the
equivalent to the report. Run everything externally sourced through
sanitize() before it is displayed, and through escape_html() before it is
written into a report page.
"""

from __future__ import annotations

import html
import re
from typing import Any

# Escape sequences, longest form first so OSC is not clipped by the Fe rule.
ESCAPE_PATTERN = re.compile(
    r'\x1B\][^\x07\x1B]*(?:\x07|\x1B\\|$)'   # OSC ... BEL / ST / truncated
    r'|\x1B\[[0-?]*[ -/]*[@-~]'              # CSI  (colours, cursor, erase)
    r'|\x1B[@-Z\\-_]'                        # other Fe escapes
    r'|\x1B.'                                # any stray escape introducer
)

# Longest untrusted value we will render on one line.
MAX_DISPLAY_LEN = 512


def sanitize(text: Any, allow_newlines: bool = False, max_len: int = MAX_DISPLAY_LEN) -> str:
    """Strip escape sequences and control characters from untrusted text.

    Control characters are dropped rather than escaped: \\r and \\b overwrite
    already-printed output just as effectively as a CSI sequence, and a bare
    \\n lets a target forge extra result lines. Newlines are kept only where
    the caller renders a genuinely multi-line block.
    """
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)

    clean = ESCAPE_PATTERN.sub('', text)

    allowed = '\n\t' if allow_newlines else '\t'
    clean = ''.join(ch for ch in clean if ch.isprintable() or ch in allowed)

    if max_len and len(clean) > max_len:
        clean = clean[:max_len] + '…'
    return clean


def escape_html(text: Any, max_len: int = MAX_DISPLAY_LEN) -> str:
    """Sanitize, then HTML-escape — for the HTML report and the web dashboard.

    Order matters: sanitize first so a crafted escape sequence cannot survive
    as a literal, then escape so markup cannot execute in the report.
    """
    return html.escape(sanitize(text, max_len=max_len), quote=True)


def escape_markdown(text: Any, max_len: int = MAX_DISPLAY_LEN) -> str:
    """Neutralise pipe characters so untrusted text cannot break a table row."""
    clean = sanitize(text, max_len=max_len)
    return clean.replace("|", "\\|").replace("\n", " ")


def sanitize_tree(value: Any, max_len: int = MAX_DISPLAY_LEN) -> Any:
    """Recursively sanitize every string inside a dict/list structure.

    Used once on the whole result before it is serialised, so a module cannot
    forget to clean one field on its way into a report.
    """
    if isinstance(value, str):
        return sanitize(value, max_len=max_len)
    if isinstance(value, dict):
        return {sanitize(str(k), max_len=128): sanitize_tree(v, max_len) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [sanitize_tree(v, max_len) for v in value]
    return value


# Anything outside this set is stripped from operator input used in filenames.
_FILENAME_SAFE = re.compile(r'[^A-Za-z0-9._-]')


def sanitize_filename(text: Any, fallback: str = 'target') -> str:
    """Reduce a string to a safe filename fragment (no separators, no dots-only)."""
    clean = _FILENAME_SAFE.sub('_', sanitize(text))
    clean = clean.strip('._')[:64]
    return clean or fallback


# A hostname we are willing to resolve, probe or print. Rejects the credential
# and path smuggling that turns a passive-source string into a request to
# somewhere we never intended to reach.
_HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))*$'
)


def valid_hostname(host: Any) -> bool:
    """True if host is a syntactically valid, printable DNS name."""
    if not host:
        return False
    host = sanitize(host, max_len=256).strip().lower().rstrip('.')
    if not host or '..' in host or '/' in host or '@' in host or ':' in host:
        return False
    return bool(_HOSTNAME_RE.match(host))


def normalise_host(host: Any) -> str:
    """Lowercase, de-wildcard and strip a hostname, or '' if unusable."""
    host = sanitize(host, max_len=256).strip().lower().rstrip('.')
    host = host.removeprefix('*.').removeprefix('.')
    if host.startswith(('http://', 'https://')):
        host = host.split('//', 1)[1]
    host = host.split('/')[0].split('?')[0].split('#')[0]
    if '@' in host:
        host = host.rsplit('@', 1)[1]
    if host.startswith('['):           # bracketed IPv6 literal
        return ''
    host = host.split(':')[0]
    return host if valid_hostname(host) else ''
