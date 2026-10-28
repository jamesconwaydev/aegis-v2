"""Copy docs/*.md into a wiki checkout: wiki.py <docs> <wiki> <ref>.

Each doc becomes a page named in PAGES, links between docs become wiki
links, and links out of docs/ point at the same files in the repository
at <ref>, so the wiki never links to a newer file than it describes.
"""

import pathlib
import re
import sys

REPO = "https://github.com/jamesconwaydev/aegis-v2"

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

LINK = re.compile(r"\]\(([^)\s]+)\)")


def rewrite(target, ref):
    if re.match(r"[a-z]+:|#", target):
        return target
    path, _, anchor = target.partition("#")
    anchor = "#" + anchor if anchor else ""
    if path in PAGES:
        return PAGES[path] + anchor
    if path.startswith("../"):
        return f"{REPO}/blob/{ref}/{path[3:]}{anchor}"
    return f"{REPO}/blob/{ref}/docs/{path}{anchor}"


def main(docs, wiki, ref):
    docs, wiki = pathlib.Path(docs), pathlib.Path(wiki)
    found = {p.name for p in docs.glob("*.md")}
    if found != set(PAGES):
        sys.exit(f"docs/ and PAGES differ: {sorted(found ^ set(PAGES))}")
    for name, page in PAGES.items():
        text = (docs / name).read_text()
        text = LINK.sub(lambda m: f"]({rewrite(m.group(1), ref)})", text)
        note = f"\n\n---\n\nFrom [`docs/{name}`]({REPO}/blob/{ref}/docs/{name}) at {ref}.\n"
        (wiki / f"{page}.md").write_text(text.rstrip() + note)
    sidebar = "\n".join(f"- [{p.replace('-', ' ')}]({p})" for p in PAGES.values())
    (wiki / "_Sidebar.md").write_text(sidebar + "\n")


if __name__ == "__main__":
    main(*sys.argv[1:])
