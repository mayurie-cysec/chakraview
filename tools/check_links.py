#!/usr/bin/env python3
"""Link and page-hygiene checker for the ChakraView web pages.

Catches the things that quietly rot in a static site: an href pointing at a
file that was renamed, an in-page anchor whose target id no longer exists, a
button styled as a link with nowhere to go, a missing title or meta
description, an oversized image.

    python3 tools/check_links.py            # internal links and page hygiene
    python3 tools/check_links.py --external # also verify external URLs resolve

Exits non-zero if anything is broken, so it can gate a commit or a CI job.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from html.parser import HTMLParser
from urllib.parse import urldefrag, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB = os.path.join(ROOT, "web")

# A PNG/GIF/JPG larger than this in a web page is worth a second look.
MAX_IMAGE_KB = 400


class PageParser(HTMLParser):
    """Collects the pieces of a page the checks need."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []      # (tag, href/src)
        self.ids: set[str] = set()
        self.anchor_names: set[str] = set()
        self.title: str = ""
        self.meta: dict[str, str] = {}
        self.has_favicon = False
        self.images: list[dict[str, str]] = []
        self.buttons: list[dict[str, str]] = []
        self.labels: list[str] = []
        self.inputs: list[dict[str, str]] = []
        self._in_title = False
        self._lang = ""
        self._label_depth = 0   # >0 while inside a <label>

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k.lower(): (v or "") for k, v in attrs}

        if "id" in attributes:
            self.ids.add(attributes["id"])

        if tag == "html":
            self._lang = attributes.get("lang", "")

        if tag == "title":
            self._in_title = True

        if tag == "meta":
            name = attributes.get("name") or attributes.get("property")
            if name:
                self.meta[name.lower()] = attributes.get("content", "")

        if tag == "link":
            rel = attributes.get("rel", "").lower()
            if "icon" in rel:
                self.has_favicon = True
            if attributes.get("href"):
                self.links.append((tag, attributes["href"]))

        if tag == "a":
            href = attributes.get("href")
            if href is not None:
                self.links.append((tag, href))
            if attributes.get("name"):
                self.anchor_names.add(attributes["name"])
            # An <a> styled as a button but pointing nowhere is a dead button.
            if "btn" in attributes.get("class", ""):
                self.buttons.append({
                    "kind": "a", "href": href or "",
                    "text": attributes.get("aria-label", ""),
                })

        if tag in ("script", "img", "source", "iframe"):
            src = attributes.get("src")
            if src:
                self.links.append((tag, src))
            if tag == "img":
                self.images.append({
                    "src": src or "",
                    "alt": attributes.get("alt", "__missing__"),
                    "width": attributes.get("width", ""),
                    "height": attributes.get("height", ""),
                })

        if tag == "button":
            self.buttons.append({
                "kind": "button",
                "type": attributes.get("type", ""),
                "id": attributes.get("id", ""),
                "data": ",".join(k for k in attributes if k.startswith("data-")),
            })

        if tag == "label":
            self._label_depth += 1
            if attributes.get("for"):
                self.labels.append(attributes["for"])

        if tag in ("input", "select", "textarea"):
            self.inputs.append({
                "id": attributes.get("id", ""),
                "type": attributes.get("type", ""),
                "aria": attributes.get("aria-label", ""),
                # An input wrapped in a <label> is labelled implicitly, which
                # is valid HTML and needs no matching for= attribute.
                "wrapped": "1" if self._label_depth > 0 else "",
            })

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        if tag == "label":
            self._label_depth = max(0, self._label_depth - 1)

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data.strip()


def parse(path: str) -> PageParser:
    parser = PageParser()
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        parser.feed(handle.read())
    return parser


def is_external(url: str) -> bool:
    return bool(urlparse(url).scheme) or url.startswith("//")


def check_page(path: str, pages: dict[str, PageParser]) -> list[str]:
    """Return a list of problems found on one page."""
    page = pages[path]
    name = os.path.relpath(path, ROOT)
    problems: list[str] = []
    directory = os.path.dirname(path)

    # ── Links ──
    for tag, raw in page.links:
        url = raw.strip()
        if not url:
            problems.append(f"{name}: <{tag}> has an empty href/src")
            continue
        if url.startswith(("mailto:", "tel:", "data:", "javascript:")):
            continue
        if is_external(url):
            continue

        target, fragment = urldefrag(url)

        if not target:
            # Same-page anchor.
            if fragment and fragment not in page.ids and fragment not in page.anchor_names:
                problems.append(f"{name}: #{fragment} does not exist on this page")
            continue

        resolved = os.path.normpath(os.path.join(directory, target))
        if os.path.isdir(resolved):
            resolved = os.path.join(resolved, "index.html")
        if not os.path.isfile(resolved):
            problems.append(f"{name}: <{tag}> → {url} (file not found)")
            continue

        if fragment and resolved in pages:
            other = pages[resolved]
            if fragment not in other.ids and fragment not in other.anchor_names:
                problems.append(
                    f"{name}: {target}#{fragment} — that id is not in "
                    f"{os.path.basename(resolved)}"
                )

    # ── Page hygiene ──
    if not page.title:
        problems.append(f"{name}: no <title>")
    elif len(page.title) > 70:
        problems.append(f"{name}: <title> is {len(page.title)} chars (keep under 70)")

    description = page.meta.get("description", "")
    if not description:
        problems.append(f"{name}: no meta description")
    elif len(description) < 50:
        problems.append(f"{name}: meta description is only {len(description)} chars")

    if not page.has_favicon:
        problems.append(f"{name}: no favicon link")

    if not page._lang:
        problems.append(f"{name}: <html> has no lang attribute")

    if "viewport" not in page.meta:
        problems.append(f"{name}: no viewport meta — the page will not be responsive")

    # ── Buttons ──
    for button in page.buttons:
        if button["kind"] == "a":
            href = button["href"].strip()
            if not href or href == "#":
                problems.append(
                    f"{name}: a button-styled link points at "
                    f"{href or '(nothing)'} — dead button"
                )
        else:
            # A <button> with no type, no id and no data-* hook has nothing
            # wired to it and nothing to find it by.
            if not button["type"] and not button["id"] and not button["data"]:
                problems.append(f"{name}: a <button> has no type, id or data hook")

    # ── Images ──
    for image in page.images:
        if image["alt"] == "__missing__":
            problems.append(f"{name}: <img src=\"{image['src']}\"> has no alt attribute")
        src = image["src"]
        if src and not is_external(src) and not src.startswith("data:"):
            resolved = os.path.normpath(os.path.join(directory, src))
            if os.path.isfile(resolved):
                kb = os.path.getsize(resolved) / 1024
                if kb > MAX_IMAGE_KB and not resolved.endswith(".svg"):
                    problems.append(
                        f"{name}: {src} is {kb:.0f} KB — compress it "
                        f"(budget {MAX_IMAGE_KB} KB)"
                    )

    # ── Form labelling ──
    for field in page.inputs:
        if field["type"] in ("hidden", "submit", "button"):
            continue
        if field["wrapped"] or field["aria"]:
            continue
        if not field["id"]:
            problems.append(f"{name}: an unwrapped {field['type'] or 'input'} "
                            "field has no id and no label")
            continue
        if field["id"] not in page.labels:
            problems.append(f"{name}: input #{field['id']} has no label")

    return problems


def check_external(pages: dict[str, PageParser]) -> list[str]:
    """Verify external URLs resolve. Network-dependent, so opt-in."""
    import urllib.error
    import urllib.request

    seen: set[str] = set()
    problems: list[str] = []
    for page in pages.values():
        for _tag, url in page.links:
            if not is_external(url) or url in seen:
                continue
            seen.add(url)
            request = urllib.request.Request(
                url, method="HEAD",
                headers={"User-Agent": "ChakraView-LinkCheck/2.0"},
            )
            try:
                with urllib.request.urlopen(request, timeout=12) as response:
                    if response.status >= 400:
                        problems.append(f"{url} → HTTP {response.status}")
            except urllib.error.HTTPError as exc:
                # Plenty of sites refuse HEAD but serve GET perfectly well.
                if exc.code in (403, 405, 999):
                    continue
                problems.append(f"{url} → HTTP {exc.code}")
            except Exception as exc:
                problems.append(f"{url} → {type(exc).__name__}")
    print(f"  checked {len(seen)} external URLs")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--external", action="store_true",
                        help="Also verify external URLs resolve")
    args = parser.parse_args()

    html_files = sorted(
        os.path.join(base, f)
        for base, _dirs, files in os.walk(WEB)
        for f in files if f.endswith(".html")
    )
    if not html_files:
        print(f"No HTML found under {WEB}")
        return 1

    pages = {path: parse(path) for path in html_files}

    print(f"\n  ChakraView link check — {len(pages)} pages\n")
    problems: list[str] = []
    for path in html_files:
        found = check_page(path, pages)
        status = "OK" if not found else f"{len(found)} problem(s)"
        print(f"  {os.path.relpath(path, ROOT):<28} {status}")
        problems.extend(found)

    if args.external:
        print()
        problems.extend(check_external(pages))

    print()
    if problems:
        print(f"  {len(problems)} problem(s):\n")
        for problem in problems:
            print(f"    - {problem}")
        print()
        return 1

    print("  No broken links, no missing metadata, no dead buttons.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
