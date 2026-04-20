import os
from dotenv import load_dotenv

# This tells Python to look at the .env file we just made
load_dotenv()

# This grabs the value labeled GITHUB_TOKEN from that file
github_token = os.getenv("fRaUPToOSb84oeF3ATlivtlD0lX2sw1KpnQG")
import argparse
import sys
import os
import time
import threading
import itertools

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from modules import shakuni, sanjaya, ashwatthama, karna, brahmastra
except ImportError as e:
    print(f"\033[31m[!] Formation Broken: Missing modules. {e}\033[0m")
    sys.exit(1)

# ─────────────────────────────────────────────
# PALETTE  (warm amber / copper / saffron — no neon)
# ─────────────────────────────────────────────
SAFFRON = '\033[38;5;208m'
COPPER  = '\033[38;5;130m'
GOLD    = '\033[33m'
BLOOD   = '\033[31m'
GREEN   = '\033[38;5;82m'
DIM     = '\033[2m'
RESET   = '\033[0m'
BOLD    = '\033[1m'
AMBER   = '\033[38;5;172m'
RUST    = '\033[38;5;166m'

# ANSI cursor / screen helpers
HIDE_CURSOR   = '\033[?25l'
SHOW_CURSOR   = '\033[?25h'
SAVE_POS      = '\033[s'
RESTORE_POS   = '\033[u'
CLEAR_LINE    = '\033[2K'
MOVE_UP       = '\033[1A'

def _write(s):
    sys.stdout.write(s)
    sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════
# SUDARSHANA CHAKRA  — 3-ring animated spinner
# Runs in a background thread; call .stop() to end it.
# ═══════════════════════════════════════════════════════════════════

# Each ring is a sequence of Unicode "frames" that give a rotation illusion.
# Outer ring  (slow, forward)
_OUTER = [
    "◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━",
    "━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━",
    "━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━",
    "━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━",
    "━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━",
    "━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━",
    "━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━",
    "━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━━━━━━━━◈━",
]

# Middle ring  (medium, reverse)
_MIDDLE_FWD = ['◉', '◎', '⊙', '◎']

# Inner ring  (fast, 8 blades)
_INNER = ['✦', '✧', '⋆', '✧']

# Full Sudarshana banner (3 lines tall, cycles through blade positions)
_CHAKRA_FRAMES = [
    [
        f"  {AMBER}    ▲    {RESET}",
        f"  {GOLD}◄  {SAFFRON}⊛{GOLD}  ►{RESET}",
        f"  {AMBER}    ▼    {RESET}",
    ],
    [
        f"  {AMBER}  ↗   ↑   {RESET}",
        f"  {GOLD}←  {SAFFRON}⊛{GOLD}  →{RESET}",
        f"  {AMBER}  ↙   ↓   {RESET}",
    ],
    [
        f"  {AMBER}    ◆    {RESET}",
        f"  {GOLD}◈  {SAFFRON}✦{GOLD}  ◈{RESET}",
        f"  {AMBER}    ◆    {RESET}",
    ],
    [
        f"  {AMBER}  ↖   ↑   {RESET}",
        f"  {GOLD}←  {SAFFRON}⊛{GOLD}  →{RESET}",
        f"  {AMBER}  ↘   ↓   {RESET}",
    ],
]

# Large centred Sudarshana — shown once on boot
_BIG_CHAKRA = r"""
        {AM}  ◆  {R}
    {AM}◈━━━━━━━◆━━━━━━━◈{R}
  {AM}◆{G}━━━━━{S}╋━━━━━{G}━━━━◆{R}
{AM}◆{G}━━━━━━━{S}●{G}━━━━━━━{AM}◆{R}
  {AM}◆{G}━━━━━{S}╋━━━━━{G}━━━━◆{R}
    {AM}◈━━━━━━━◆━━━━━━━◈{R}
        {AM}  ◆  {R}"""


class ChakraSpinner:
    """
    Animated Sudarshana Chakra that spins beside a status message.
    Usage:
        sp = ChakraSpinner("Scanning GitHub...")
        sp.start()
        # ... do work ...
        sp.stop("Done")
    """
    _BLADES  = ['⊕', '✦', '⊗', '✧', '⊕', '✦', '⊗', '✧']
    _RING_CW = ['━◈━━━━◈', '━━◈━━━◈', '━━━◈━━◈', '━━━━◈━◈',
                '━━━━━◈◈', '━━━━◈━◈', '━━━◈━━◈', '━━◈━━━◈']
    _RING_CC = _RING_CW[::-1]

    def __init__(self, message=''):
        self.message  = message
        self._stop_ev = threading.Event()
        self._thread  = threading.Thread(target=self._spin, daemon=True)

    def start(self):
        _write(HIDE_CURSOR)
        self._thread.start()
        return self

    def stop(self, done_msg=None):
        self._stop_ev.set()
        self._thread.join()
        _write(f'\r{CLEAR_LINE}')
        if done_msg:
            print(f'  {GREEN}✓{RESET}  {done_msg}')
        _write(SHOW_CURSOR)

    def set_message(self, msg):
        self.message = msg

    def _spin(self):
        frames = itertools.cycle(range(8))
        for i in frames:
            if self._stop_ev.is_set():
                break
            blade  = self._BLADES[i]
            cw     = self._RING_CW[i % len(self._RING_CW)]
            inner  = f'{SAFFRON}{blade}{RESET}'
            outer  = f'{AMBER}{cw}{RESET}'
            line   = (f'\r  {outer} {inner} '
                      f'{GOLD}{self.message}{RESET}'
                      f'{DIM}{"." * (i % 4 + 1)}{RESET}   ')
            _write(line)
            time.sleep(0.12)


# ═══════════════════════════════════════════════════════════════════
# RADAR BAR — used while karna subdomain scan runs
# ═══════════════════════════════════════════════════════════════════

_RADAR_SWEEP = ['⠋','⠙','⠹','⠸','⠼','⠴','⠦','⠧','⠇','⠏']
_RADAR_PULSE = ['·', '•', '◉', '•', '·']

def radar_bar(label, current, total, hits, width=30):
    """Print a single-line radar progress bar (overwrite with \\r)."""
    frac    = current / max(total, 1)
    filled  = int(width * frac)
    bar     = f"{AMBER}{'━' * filled}{DIM}{'╌' * (width - filled)}{RESET}"
    pct     = int(frac * 100)
    sweep_i = current % len(_RADAR_SWEEP)
    sweep   = f"{GREEN}{_RADAR_SWEEP[sweep_i]}{RESET}"
    hit_clr = BLOOD if hits else DIM
    line    = (f'\r  {sweep} {bar} '
               f'{GOLD}{pct:3d}%{RESET}  '
               f'{COPPER}{label}{RESET}  '
               f'{hit_clr}⚔ {hits} hits{RESET}   ')
    _write(line)


# ═══════════════════════════════════════════════════════════════════
# PARTICLE BURST  — printed once at scan-complete
# ═══════════════════════════════════════════════════════════════════

_BURST_FRAMES = [
    # (radius, chars, colour)
    (1,  '·',  AMBER),
    (2,  '•',  GOLD),
    (3,  '◈',  SAFFRON),
    (4,  '✦',  COPPER),
    (5,  '·',  DIM),
]

def particle_burst(width=72):
    """Animate a brief radial burst in the terminal."""
    cx = width // 2
    for r, ch, col in _BURST_FRAMES:
        line = [' '] * width
        for pos in [cx - r*2, cx + r*2, cx - r, cx + r]:
            if 0 <= pos < width:
                line[pos] = ch
        _write(f'\r  {col}{"".join(line)}{RESET}')
        time.sleep(0.07)
    _write(f'\r{" " * (width + 4)}\r')   # clear


def animate_scroll(text, speed=0.015):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(speed)
    print()


# ═══════════════════════════════════════════════════════════════════
# BORDERS / HEADERS  (unchanged contract, enhanced look)
# ═══════════════════════════════════════════════════════════════════

def draw_border():
    print(f"{COPPER}⚔{'━'*71}⚔{RESET}")

def draw_mini_border():
    print(f"{DIM}  {'─'*69}{RESET}")

def section_header(chakra_num, icon, title, subtitle):
    print()
    # Tiny chakra pip beside each header
    pip = f"{SAFFRON}⊛{RESET}"
    print(f"  {pip} {BOLD}{GOLD}{icon}  CHAKRA {chakra_num}: {title}{RESET}")
    print(f"     {DIM}{subtitle}{RESET}")
    draw_mini_border()

def status_line(label, value, color=None):
    c = color if color else COPPER
    print(f"  {c}◈ {label}:{RESET} {value}")


# ═══════════════════════════════════════════════════════════════════
# BANNER  — with big animated chakra on boot
# ═══════════════════════════════════════════════════════════════════

def banner():
    # Big ASCII art (unchanged)
    art = f"""
{SAFFRON}{BOLD}
   ██████╗██╗  ██╗ █████╗ ██╗  ██╗██████╗  █████╗ ██╗   ██╗██╗███████╗██╗    ██╗
  ██╔════╝██║  ██║██╔══██╗██║ ██╔╝██╔══██╗██╔══██╗██║   ██║██║██╔════╝██║    ██║
  ██║     ███████║███████║█████╔╝ ██████╔╝███████║██║   ██║██║█████╗  ██║ █╗ ██║
  ██║     ██╔══██║██╔══██║██╔═██╗ ██╔══██╗██╔══██║╚██╗ ██╔╝██║██╔══╝  ██║███╗██║
  ╚██████╗██║  ██║██║  ██║██║  ██╗██║  ██║██║  ██║ ╚████╔╝ ██║███████╗╚███╔███╔╝
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝ ╚══╝╚══╝
{COPPER}                    ═══ THE STRATEGIC BATTLE FORMATION ═══
{DIM}                         Authorized Recon Use Only{RESET}
    """
    print(art)

    # Animated Sudarshana on boot — spin for ~1.2 s
    _write(HIDE_CURSOR)
    spin_chars = ['⊕','✦','⊗','✧','◈','✦','⊕','⊗']
    ring_cw    = ['━◈━━◈━━◈','━━◈━━◈━━','━━━◈━━◈━','━━◈━━◈━━']
    ring_cc    = ring_cw[::-1]

    for i in range(20):
        blade  = spin_chars[i % len(spin_chars)]
        outer  = ring_cw[i % len(ring_cw)]
        inner  = ring_cc[i % len(ring_cc)]
        label_states = ['Preparing Vyuha...', 'Awakening Shakuni...', 'Arming Brahmastra...', 'Blowing the Shankh...']
        label  = label_states[(i // 5) % len(label_states)]
        _write(f'\r  {AMBER}{outer}{RESET}  '
               f'{SAFFRON}{BOLD}{blade}{RESET}  '
               f'{AMBER}{inner}{RESET}  '
               f'{DIM}{label}{RESET}   ')
        time.sleep(0.08)

    _write(f'\r{CLEAR_LINE}')
    _write(SHOW_CURSOR)


# ═══════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog='chakraview',
        description='ChakraView — Strategic Recon Formation for Security Researchers'
    )
    parser.add_argument('-d', '--domain',     required=True,      help='Target domain (e.g. example.com)')
    parser.add_argument('--no-archive',       action='store_true', help='Skip Wayback Machine scan')
    parser.add_argument('--no-github',        action='store_true', help='Skip GitHub OSINT')
    parser.add_argument('--report',           action='store_true', help='Save full report to file')
    args = parser.parse_args()

    target = (
        args.domain.strip().lower()
        .replace("http://", "")
        .replace("https://", "")
        .split('/')[0]
    )

    os.system('clear')
    banner()

    animate_scroll(
        f"  {SAFFRON}🚩 Blowing the Shankh... Breaching the first layer of the Vyuha.{RESET}",
        0.025
    )

    draw_border()
    print(f"  {BOLD}{SAFFRON}🚩 TARGET FORTRESS:{RESET}  {BOLD}{GOLD}{target.upper()}{RESET}")
    print(f"  {DIM}Scan started at: {time.strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    draw_border()


    # ─────────────────────────────────────────────
    # CHAKRA I — SHAKUNI  (GitHub OSINT)
    # ─────────────────────────────────────────────
    section_header("I", "🏹", "SHAKUNI'S STRATEGY",
                   "Scanning GitHub for architects, repos, and leaked secrets...")

    s_data = {"count": 0, "names": [], "repos": []}

    if not args.no_github:
        sp = ChakraSpinner("Probing GitHub architects").start()
        s_data = shakuni.run(target)
        sp.stop()

        if s_data['count'] not in (0, "Error"):
            status_line("Architects Identified", str(s_data['count']), SAFFRON)

            if s_data.get('names'):
                print(f"\n  {SAFFRON}◈ All Architects ({len(s_data['names'])} total):{RESET}")
                for i, name in enumerate(s_data['names'], 1):
                    print(f"    {DIM}[{i:03d}]{RESET} {COPPER}{name}{RESET}")

            if s_data.get('repos'):
                print(f"\n  {SAFFRON}◈ Repositories / Leaks Found:{RESET}")
                for repo in s_data['repos'][:8]:
                    tag = (f"{BLOOD}[LEAK]{RESET}" if "[LEAK]" in repo
                           else f"{COPPER}[REPO]{RESET}")
                    print(f"    {tag} {repo}")
                if len(s_data['repos']) > 8:
                    print(f"    {DIM}... and {len(s_data['repos']) - 8} more in report{RESET}")
        else:
            status_line("GitHub Layer",
                        "Silent / Rate-limited. Set GITHUB_TOKEN env var.", BLOOD)
    else:
        status_line("GitHub Scan", "Skipped (--no-github)", DIM)


    # ─────────────────────────────────────────────
    # CHAKRA II — SANJAYA  (IP / Infra Shadow)
    # ─────────────────────────────────────────────
    section_header("II", "👁 ", "SANJAYA'S DRISHTI",
                   "Resolving infrastructure, ASN, and CDN detection...")

    sp = ChakraSpinner("Resolving IP & ASN").start()
    j_data = sanjaya.run(target)
    sp.stop()

    status_line("IP Address",   j_data.get('ip', 'Unknown'))
    status_line("Organization", j_data.get('org', 'Unknown'))
    status_line("Location",     f"{j_data.get('city','?')}, {j_data.get('country','?')}")
    status_line("Reverse DNS",  j_data.get('reverse_dns', 'None'))

    if j_data.get('cdn'):
        print(f"\n  {BLOOD}{BOLD}⚠  CDN/WAF DETECTED — Real IP is masked!{RESET}")
        animate_scroll(f"  {BLOOD}   {j_data.get('observation', '')}{RESET}", 0.015)
    else:
        print(f"\n  {GREEN}✓  Direct IP exposed — No CDN layer detected.{RESET}")
        status_line("Observation", j_data.get('observation', ''), GREEN)


    # ─────────────────────────────────────────────
    # CHAKRA III — ASHWATTHAMA  (Wayback Archaeology)
    # ─────────────────────────────────────────────
    section_header("III", "🏺", "ASHWATTHAMA'S MEMORY",
                   "Excavating the Wayback Machine for buried secrets...")

    a_data = {"found": False, "paths": [], "note": "Skipped"}

    if not args.no_archive:
        sp = ChakraSpinner("Excavating archives").start()
        a_data = ashwatthama.run(target)
        sp.stop()

        status_line(
            "Archive Status",
            f"{'✓ Paths Found' if a_data.get('found') else '✗ Nothing Sensitive'}"
        )
        status_line("Note", a_data.get('note', ''))

        if a_data.get('paths'):
            print(f"\n  {SAFFRON}◈ High-Value Archived Paths:{RESET}")
            for path in a_data['paths']:
                print(f"    {BLOOD}📜{RESET} {path}")
        else:
            print(f"  {DIM}  No sensitive paths surfaced from the archives.{RESET}")
    else:
        status_line("Archive Scan", "Skipped (--no-archive)", DIM)


    # ─────────────────────────────────────────────
    # CHAKRA IV — KARNA  (Subdomain Recon)
    # — radar bar printed live via karna's own print,
    #   we wrap only the section header / summary
    # ─────────────────────────────────────────────
    section_header("IV", "🛡 ", "KARNA'S LOGIC",
                   "Probing critical subdomains and exposed infrastructure...")

    # Patch karna's live-print line to include radar bar style
    # (karna.run already prints each hit live — we just add a finishing radar)
    _write(HIDE_CURSOR)
    k_data = karna.run(target)
    _write(SHOW_CURSOR)

    # Print final radar sweep animation after karna finishes
    found_subs = k_data.get('found', [])
    total_probed = len(karna.CRITICAL_SUBS) if hasattr(karna, 'CRITICAL_SUBS') else 200

    print()
    for step in range(0, total_probed + 1, max(1, total_probed // 30)):
        radar_bar("SUBDOMAINS", step, total_probed, len(found_subs))
        time.sleep(0.01)
    radar_bar("SUBDOMAINS", total_probed, total_probed, len(found_subs))
    print()   # newline after bar

    if found_subs:
        print(f"\n  {BLOOD}{BOLD}◈ {k_data['intelligence']}{RESET}")
        print(f"\n  {SAFFRON}Subdomain Summary:{RESET}")
        for i, sub in enumerate(found_subs, 1):
            proto_color = (GREEN  if sub['proto'] == 'https' else
                           COPPER if sub['proto'] == 'http'  else DIM)
            print(
                f"    {DIM}[{i:03d}]{RESET} "
                f"{BOLD}{sub['host']}{RESET}  "
                f"{proto_color}[{sub['proto'].upper()}]{RESET}  "
                f"{DIM}→ {sub['ip']}{RESET}"
            )
    else:
        print(f"  {GREEN}◈ {k_data['intelligence']}{RESET}")


    # ─────────────────────────────────────────────
    # CHAKRA V — BRAHMASTRA  (Google Dorks)
    # ─────────────────────────────────────────────
    section_header("V", "🔥", "THE BRAHMASTRA UNLEASHED",
                   "Generating precision dork payloads for manual recon...")

    animate_scroll(
        f"  {BLOOD}Reciting ancient mantras... The earth trembles.{RESET}",
        0.03
    )
    print()

    b_data = brahmastra.run(target, techs=s_data.get('names', []))

    for i, dork in enumerate(b_data['dorks'], 1):
        time.sleep(0.07)
        print(f"  {BLOOD}[{i:02d}]{RESET} {dork}")


    # ─────────────────────────────────────────────
    # BATTLE SUMMARY TABLE
    # ─────────────────────────────────────────────
    print()
    draw_border()
    print(f"  {BOLD}{GOLD}📋  BATTLE SUMMARY — {target.upper()}{RESET}")
    draw_border()

    summary_rows = [
        ("Architects Found (GitHub)",  str(s_data.get('count', 0)),           SAFFRON),
        ("Repos / Leaks Detected",     str(len(s_data.get('repos', []))),      BLOOD if s_data.get('repos') else COPPER),
        ("Target IP",                  j_data.get('ip', 'Unknown'),            COPPER),
        ("CDN / WAF Detected",         "YES — Real IP masked" if j_data.get('cdn') else "No",
                                                                               BLOOD if j_data.get('cdn') else GREEN),
        ("Archive Sensitive Paths",    str(len(a_data.get('paths', []))),      BLOOD if a_data.get('paths') else COPPER),
        ("Live Critical Subdomains",   str(len(found_subs)),                   BLOOD if found_subs else GREEN),
        ("Dork Payloads Ready",        str(len(b_data.get('dorks', []))),      SAFFRON),
    ]

    for label, value, color in summary_rows:
        print(f"  {DIM}{label:<35}{RESET}  {color}{BOLD}{value}{RESET}")

    draw_border()


    # ─────────────────────────────────────────────
    # PARTICLE BURST  — Brahmastra finale
    # ─────────────────────────────────────────────
    print()
    animate_scroll(f"  {AMBER}Unleashing Brahmastra...{RESET}", 0.03)
    time.sleep(0.2)

    for _ in range(3):
        particle_burst(72)

    # Final victory line with slow scroll
    print()
    animate_scroll(
        f"  {BOLD}{SAFFRON}⚔  THE VYUHA IS BREACHED. DATA SECURED. DHARMA PREVAILS.  ⚔{RESET}",
        0.035
    )
    print()


    # ─────────────────────────────────────────────
    # OPTIONAL REPORT SAVE  (unchanged)
    # ─────────────────────────────────────────────
    if args.report:
        report_path = f"chakraview_{target}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
        with open(report_path, 'w') as f:
            f.write(f"CHAKRAVIEW REPORT — {target}\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")

            f.write("[ SHAKUNI — GitHub OSINT ]\n")
            f.write(f"Architects: {s_data.get('count', 0)}\n")
            f.write(f"Names: {', '.join(s_data.get('names', []))}\n")
            f.write("Repos/Leaks:\n")
            for r in s_data.get('repos', []):
                f.write(f"  {r}\n")

            f.write("\n[ SANJAYA — Infrastructure ]\n")
            f.write(f"IP: {j_data.get('ip')}\n")
            f.write(f"Org: {j_data.get('org')}\n")
            f.write(f"CDN: {'Yes' if j_data.get('cdn') else 'No'}\n")
            f.write(f"Reverse DNS: {j_data.get('reverse_dns')}\n")

            f.write("\n[ ASHWATTHAMA — Archive Paths ]\n")
            for p in a_data.get('paths', []):
                f.write(f"  {p}\n")

            f.write("\n[ KARNA — Live Subdomains ]\n")
            for sub in found_subs:
                f.write(f"  {sub['url']}  [{sub['ip']}]\n")

            f.write("\n[ BRAHMASTRA — Google Dorks ]\n")
            for dork in b_data.get('dorks', []):
                f.write(f"  {dork}\n")

        print(f"\n  {GREEN}{BOLD}[✓] Report saved → {report_path}{RESET}")

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        _write(SHOW_CURSOR)
        print(f"\n\n  {BLOOD}[!] Aborting... Retreating from Kurukshetra.{RESET}\n")
        sys.exit(0)
