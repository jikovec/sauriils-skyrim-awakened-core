"""Check public Git inventories and relative Markdown links without network access."""

import argparse
from pathlib import Path
import re
import subprocess
from urllib.parse import unquote


POLICIES = {
    "core": (
        r"(?:(?:docs|contracts|src/skyforge|\.agent|\.github|scripts)/[\w./-]+|"
        r"(?:[A-Z][A-Z0-9_-]*\.md|LICENSE|LICENSES/[\w.-]+\.txt|THIRD_PARTY_NOTICES\.md|"
        r"flake\.(?:nix|lock)|\.gitignore|\.gitattributes))",
        {".md", ".txt", ".yml", ".yaml", ".json", ".rs", ".toml", ".lock", ".nix", ".py", ".sh"},
        {"LICENSE", ".gitignore", ".gitattributes", ".github/CODEOWNERS", "scripts/check"},
    ),
    "collection": (
        r"(?:(?:collection|docs|\.agent|\.github|scripts)/[\w./-]+|"
        r"(?:[A-Z][A-Z0-9_-]*\.md|LICENSE|\.gitignore|\.gitattributes))",
        {".md", ".json", ".tsv", ".yml", ".yaml", ".py", ".sh"},
        {"LICENSE", ".gitignore", ".gitattributes", ".github/CODEOWNERS", "scripts/check"},
    ),
}
PROTECTED_COMPONENT = re.compile(
    r"^(?:\.env(?:\..*)?|saves?|downloads?|stock-game|mo2|"
    r"databases?|volumes?|models?|private|credentials?|transcripts?|target|cache)$", re.I
)
PRIVATE_CONTENT = re.compile(
    r"/(?:home|srv)/[\w.~-]+|/games/(?:SteamLibrary|skyrim-ai-overhaul)\b|"
    r"/games/[\w.~-]+/|/run/user/\d+|file:///|"
    r"(?i:github_pat_[a-z0-9_]{22,}|gh[pousr]_[a-z0-9]{30,}|"
    r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----)"
)
LINK = re.compile(r"\[[^\]\n]+\]\(([^()\s]+)\)")


def verify(root, scope):
    paths, suffixes, exceptions = POLICIES[scope]
    index = subprocess.check_output(["git", "ls-files", "--stage", "-z"], cwd=root)
    entries = {}
    for record in index.split(b"\0"):
        if record:
            header, name = record.decode("utf-8").split("\t", 1)
            mode, _, stage = header.split()
            if stage != "0":
                raise ValueError("unmerged Git index entry")
            entries[Path(name)] = mode

    errors = []
    for path, mode in entries.items():
        name = path.as_posix()
        if (mode not in {"100644", "100755"} or ".." in path.parts
                or not re.fullmatch(paths, name)
                or (name not in exceptions and path.suffix not in suffixes)
                or any(PROTECTED_COMPONENT.fullmatch(part) for part in path.parts)):
            errors.append(f"disallowed path or mode: {name}")
            continue
        full = root / path
        if not full.is_file() or full.resolve() != full:
            errors.append(f"tracked file missing or redirected: {name}")
            continue
        payload = full.read_bytes()
        if len(payload) > 1024 * 1024 or b"\0" in payload:
            errors.append(f"oversized or nontext tracked file: {name}")
            continue
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"non-UTF-8 tracked file: {name}")
            continue
        if name != "scripts/verify-public.py" and PRIVATE_CONTENT.search(text):
            errors.append(f"possible private locator or credential: {name}")
        if path.suffix == ".md":
            for link in LINK.findall(text):
                if ":" in link or link.startswith("#"):
                    continue
                target = (full.parent / unquote(link.split("#", 1)[0])).resolve()
                if not target.is_relative_to(root) or not (
                    target.relative_to(root) in entries
                    or target.is_dir() and any(
                        item.is_relative_to(target.relative_to(root)) for item in entries)
                ):
                    errors.append(f"untracked or missing relative link: {name} → {link}")
    if errors:
        raise ValueError("\n".join(errors))
    print(f"PASS: {len(entries)} tracked public {scope} files and relative links")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=POLICIES, default="core")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        verify(args.root.resolve(), args.scope)
    except ValueError as error:
        parser.exit(1, f"{error}\n")
