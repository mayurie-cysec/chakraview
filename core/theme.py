"""Single source of truth for the ChakraView palette.

The terminal and the web UI are meant to look like the same product, so the
hex values here are the same ones declared as CSS custom properties in
web/assets/css/chakraview.css. Change a colour in one place and change it in
the other; CSS_TOKENS exists so `--dump-theme` can prove they still agree.

A temple sanctum at night: a warm black-brown ground rather than a cold
black, bhagwa saffron through marigold for the lamplight, brass for the
chakra and for target names, and sindoor red for what is urgent. Mor-pankh
teal is the one cool colour, kept for the LOW severity badge so the severity
scale does not collapse into a single band of orange.
"""

from __future__ import annotations

# ── Ground ────────────────────────────────────────────────────────────────
VOID = "#0c0705"  # page background
ABYSS = "#130c07"  # panel background
SURFACE = "#1d1309"  # raised surface
BORDER = "#3d2615"  # hairline

# ── Bhagwa scale (ember → saffron → marigold) ─────────────────────────────
EMBER = "#9a3412"
BHAGWA = "#e05c0c"
SAFFRON = "#ff7a18"
MARIGOLD = "#fcb13f"
DIYA = "#ff8c1a"

# ── Sacred accents (the chakra, the target, victory lines) ────────────────
BRASS = "#f5c542"
HALDI = "#e8a317"
SINDOOR = "#c2410c"

# ── Text ──────────────────────────────────────────────────────────────────
TEXT = "#fdf4e3"
MUTED = "#cdae86"
FAINT = "#937154"

# ── Severity ──────────────────────────────────────────────────────────────
SEV_CRITICAL = "#ff2e4e"
SEV_HIGH = "#ff7a18"
SEV_MEDIUM = "#f5c542"
SEV_LOW = "#2dd4bf"
SEV_INFO = "#c0a583"

OK = "#93c943"
WARN = "#f5c542"
FAIL = "#ff2e4e"


# Rich style table. Keys are referenced as style names all over core/ui.py.
RICH_STYLES: dict[str, str] = {
    "cv.void": VOID,
    "cv.panel": f"on {ABYSS}",
    "cv.border": BORDER,
    "cv.bhagwa": BHAGWA,
    "cv.saffron": SAFFRON,
    "cv.marigold": MARIGOLD,
    "cv.diya": DIYA,
    "cv.brass": BRASS,
    "cv.haldi": HALDI,
    "cv.sindoor": SINDOOR,
    "cv.text": TEXT,
    "cv.muted": MUTED,
    "cv.faint": FAINT,
    "cv.ok": OK,
    "cv.warn": WARN,
    "cv.fail": FAIL,
    "cv.target": f"bold {BRASS}",
    "cv.chakra": f"bold {SAFFRON}",
    "cv.sparkle": MARIGOLD,
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
    "--ember": EMBER,
    "--bhagwa": BHAGWA,
    "--saffron": SAFFRON,
    "--marigold": MARIGOLD,
    "--diya": DIYA,
    "--brass": BRASS,
    "--haldi": HALDI,
    "--sindoor": SINDOOR,
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
