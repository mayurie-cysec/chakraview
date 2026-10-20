"""Single source of truth for the ChakraView palette.

The terminal and the web UI are meant to look like the same product, so the
hex values here are the same ones declared as CSS custom properties in
web/assets/css/chakraview.css. Change a colour in one place and change it in
the other; CSS_TOKENS exists so `--dump-theme` can prove they still agree.

Deep purple + near-black ground, violet mid-tones, and a saffron/gold accent
reserved for the chakra itself and for target names.
"""

from __future__ import annotations

# ── Ground ────────────────────────────────────────────────────────────────
VOID = "#09060f"  # page background
ABYSS = "#0b0713"  # panel background
SURFACE = "#130c1f"  # raised surface
BORDER = "#2a1b3d"  # hairline

# ── Purple scale ──────────────────────────────────────────────────────────
PURPLE_DEEP = "#5b21b6"
PURPLE = "#7c3aed"
VIOLET = "#a855f7"
LILAC = "#c084fc"
ORB = "#9333ea"

# ── Mahabharata accent (the chakra, the target, victory lines) ────────────
GOLD = "#fbbf24"
SAFFRON = "#f59e0b"
COPPER = "#d97706"

# ── Text ──────────────────────────────────────────────────────────────────
TEXT = "#ede9fe"
MUTED = "#9f8fc0"
FAINT = "#6b5b8a"

# ── Severity ──────────────────────────────────────────────────────────────
SEV_CRITICAL = "#ff3366"
SEV_HIGH = "#ff7a45"
SEV_MEDIUM = "#fbbf24"
SEV_LOW = "#38bdf8"
SEV_INFO = "#8b7cb8"

OK = "#34d399"
WARN = "#fbbf24"
FAIL = "#ff3366"


# Rich style table. Keys are referenced as style names all over core/ui.py.
RICH_STYLES: dict[str, str] = {
    "cv.void": VOID,
    "cv.panel": f"on {ABYSS}",
    "cv.border": BORDER,
    "cv.purple": PURPLE,
    "cv.violet": VIOLET,
    "cv.lilac": LILAC,
    "cv.orb": ORB,
    "cv.gold": GOLD,
    "cv.saffron": SAFFRON,
    "cv.copper": COPPER,
    "cv.text": TEXT,
    "cv.muted": MUTED,
    "cv.faint": FAINT,
    "cv.ok": OK,
    "cv.warn": WARN,
    "cv.fail": FAIL,
    "cv.target": f"bold {GOLD}",
    "cv.chakra": f"bold {VIOLET}",
    "cv.sparkle": LILAC,
    "sev.critical": f"bold {SEV_CRITICAL}",
    "sev.high": f"bold {SEV_HIGH}",
    "sev.medium": SEV_MEDIUM,
    "sev.low": SEV_LOW,
    "sev.info": SEV_INFO,
}

# Mirrors :root in web/assets/css/chakraview.css.
CSS_TOKENS: dict[str, str] = {
    "--void": VOID,
    "--abyss": ABYSS,
    "--surface": SURFACE,
    "--border": BORDER,
    "--purple-deep": PURPLE_DEEP,
    "--purple": PURPLE,
    "--violet": VIOLET,
    "--lilac": LILAC,
    "--orb": ORB,
    "--gold": GOLD,
    "--saffron": SAFFRON,
    "--copper": COPPER,
    "--text": TEXT,
    "--muted": MUTED,
    "--faint": FAINT,
    "--sev-critical": SEV_CRITICAL,
    "--sev-high": SEV_HIGH,
    "--sev-medium": SEV_MEDIUM,
    "--sev-low": SEV_LOW,
    "--sev-info": SEV_INFO,
    "--ok": OK,
    "--warn": WARN,
    "--fail": FAIL,
}

SPARKLE = "✦"
PIP = "⊛"
BLADE = "◈"
SWORD = "⚔"
