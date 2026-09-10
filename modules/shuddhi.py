"""
SHUDDHI — purification of untrusted text before it reaches the terminal.

Every string ChakraView renders that came from a third party (GitHub logins
and repo names, PTR records, ipinfo org strings, archived URLs, resolved
subdomain hosts) is attacker-influenced. Raw ANSI escape sequences in that
data let a target repaint the analyst's terminal: clear reported leaks with
\x1b[2K, reposition the cursor with \x1b[H, or retitle the window with an OSC
sequence. Run everything externally sourced through sanitize() first.
"""

import re

# Escape sequences, longest form first so OSC is not clipped by the Fe rule.
ESCAPE_PATTERN = re.compile(
    r'\x1B\][^\x07\x1B]*(?:\x07|\x1B\\|$)'   # OSC ... BEL / ST / truncated
    r'|\x1B\[[0-?]*[ -/]*[@-~]'              # CSI  (colours, cursor, erase)
    r'|\x1B[@-Z\\-_]'                        # other Fe escapes
    r'|\x1B.'                                # any stray escape introducer
)

# Longest untrusted value we will render on one line.
MAX_DISPLAY_LEN = 512


def sanitize(text, allow_newlines=False, max_len=MAX_DISPLAY_LEN):
    """Strip escape sequences and control characters from untrusted text.

    Control characters are dropped rather than escaped: \\r and \\b overwrite
    already-printed output just as effectively as a CSI sequence, and a bare
    \\n lets a target forge extra result lines. Newlines are kept only where
    the caller renders a genuinely multi-line block.
    """
    if not isinstance(text, str):
        text = str(text)

    clean = ESCAPE_PATTERN.sub('', text)

    allowed = '\n\t' if allow_newlines else '\t'
    clean = ''.join(ch for ch in clean if ch.isprintable() or ch in allowed)

    if max_len and len(clean) > max_len:
        clean = clean[:max_len] + '…'
    return clean


# Anything outside this set is stripped from operator input used in filenames.
_FILENAME_SAFE = re.compile(r'[^A-Za-z0-9._-]')


def sanitize_filename(text, fallback='target'):
    """Reduce a string to a safe filename fragment (no separators, no dots-only)."""
    clean = _FILENAME_SAFE.sub('_', sanitize(text))
    clean = clean.strip('._')[:64]
    return clean or fallback
