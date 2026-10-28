"""Copy docs/*.md into a wiki checkout: wiki.py <docs> <wiki> <ref>.

`wiki.py --check` runs the link-rewrite self-check.

Each doc becomes a page named in PAGES, links between docs become wiki
links, and links out of docs/ point at the same files in the repository
at <ref>, so the wiki never links to a newer file than it describes.
"""

import pathlib
import posixpath
import re
import sys

# doc file -> wiki page, in sidebar order
PAGES = {
    "README.md": "Home",
    "overview.md": "Overview",
    "installation.md": "Installation",
    "preflight.md": "Preflight",
    "configuration.md": "Configuration",
    "scoring.md": "Scoring",
    "incidents.md": "Incidents",
    "telemetry.md": "Telemetry",
    "aegisctl.md": "aegisctl",
    "selinux.md": "SELinux",
    "threat-model.md": "Threat-model",
    "troubleshooting.md": "Troubleshooting",
    "faq.md": "FAQ",
    "architecture.md": "Architecture",
    "development.md": "Development",
    "releasing.md": "Releasing",
    "roadmap.md": "Roadmap",
}

REPO_PATH = "jamesconwaydev/aegis-v2"
REPO = f"https://github.com/{REPO_PATH}"

# Inline links and images, with an optional title, and reference-style
# definitions. Targets with spaces or nested brackets aren't supported.
INLINE = re.compile(r'(!?)\[([^\]]*)\]\(([^)\s]+)((?:\s+"[^"]*")?)\)')
REFDEF = re.compile(r"^( {0,3}\[[^\]]+\]:[ \t]*)(\S+)", re.M)


def rewrite(target, ref, image=False):
    if re.match(r"[a-z]+:|#", target):
        return target
    path, _, anchor = target.partition("#")
    anchor = "#" + anchor if anchor else ""
    full = posixpath.normpath(posixpath.join("docs", path))
    if full.startswith("../") or full == "..":
        sys.exit(f"link leaves the repository: {target}")
    if not image and posixpath.dirname(full) == "docs" and posixpath.basename(full) in PAGES:
        return PAGES[posixpath.basename(full)] + anchor
    if image:
        return f"https://raw.githubusercontent.com/{REPO_PATH}/{ref}/{full}"
    return f"{REPO}/blob/{ref}/{full}{anchor}"


def convert(text, ref):
    def inline(m):
        bang, label, target, title = m.groups()
        return f"{bang}[{label}]({rewrite(target, ref, bool(bang))}{title})"

    text = INLINE.sub(inline, text)
    return REFDEF.sub(lambda m: m.group(1) + rewrite(m.group(2), ref), text)


def check():
    """Asserts the rewrites on a fixture: wiki.py --check."""
    blob, raw = f"{REPO}/blob/v9", f"https://raw.githubusercontent.com/{REPO_PATH}/v9"
    cases = {
        "[a](faq.md)": "[a](FAQ)",
        "[a](./faq.md#x)": "[a](FAQ#x)",
        '[a](faq.md "t")': '[a](FAQ "t")',
        "[a](#here)": "[a](#here)",
        "[a](https://x.org/y.md)": "[a](https://x.org/y.md)",
        "[a](../CHANGELOG.md#s)": f"[a]({blob}/CHANGELOG.md#s)",
        "[a](../examples/lab)": f"[a]({blob}/examples/lab)",
        "[a](sub/../faq.md)": "[a](FAQ)",
        "![g](../assets/x.gif)": f"![g]({raw}/assets/x.gif)",
        '![g](./pic.png "t")': f'![g]({raw}/docs/pic.png "t")',
        "[x]: ../SECURITY.md": f"[x]: {blob}/SECURITY.md",
        "  [y]: ./roadmap.md#v1": "  [y]: Roadmap#v1",
        "[z]: https://x.org": "[z]: https://x.org",
    }
    for given, want in cases.items():
        got = convert(given, "v9")
        assert got == want, f"{given!r}: got {got!r}, want {want!r}"
    print(f"wiki.py: {len(cases)} rewrites ok")


def main(docs, wiki, ref):
    docs, wiki = pathlib.Path(docs), pathlib.Path(wiki)
    found = {p.name for p in docs.glob("*.md")}
    if found != set(PAGES):
        sys.exit(f"docs/ and PAGES differ: {sorted(found ^ set(PAGES))}")
    for name, page in PAGES.items():
        text = (docs / name).read_text()
        text = convert(text, ref)
        note = f"\n\n---\n\nFrom [`docs/{name}`]({REPO}/blob/{ref}/docs/{name}) at {ref}.\n"
        (wiki / f"{page}.md").write_text(text.rstrip() + note)
    sidebar = "\n".join(f"- [{p.replace('-', ' ')}]({p})" for p in PAGES.values())
    (wiki / "_Sidebar.md").write_text(sidebar + "\n")


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    else:
        main(*sys.argv[1:])
