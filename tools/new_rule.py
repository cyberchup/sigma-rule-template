"""Start a new Sigma rule from templates/rule.yml.

    python tools/new_rule.py rules/windows/process_creation/proc_creation_win_certutil_download.yml --title "Potential File Download Via Certutil.EXE"

Copies the template without its comments and fills in what needs no judgment: a fresh id,
today's date, the author (`git config user.name` unless --author is given), the title (with
--title) and the logsource, from --category/--product/--service or, failing those, from
the folder when it follows SigmaHQ's layout (tools/logsources.py). `related` and `license`
are kept, with the upstream id filled in, only for a rule adapted from another one
(--derived-from). Every other <placeholder> is left for the rule's author and listed at the
end; tools/check_rule.py fails a rule that still has one.

The rule can go anywhere, including another repository: the path is relative to the
current directory and the template is found next to this script.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
import sys
import uuid
from pathlib import Path

import yaml

import logsources

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "rule.yml"
FILE_NAME = re.compile(r"[a-z0-9_]+\.yml")
PLACEHOLDER = re.compile(r"<[^<>\n]+>")
LOGSOURCE_KEYS = re.compile(r"^(logsource:\n)((?:    (?:category|product|service): .*\n)+)", re.MULTILINE)
RELATED_BLOCK = re.compile(r"^related:\n(?: {4,}.*\n)+", re.MULTILINE)
LICENSE_LINE = re.compile(r"^license: .*\n", re.MULTILINE)


def strip_comments(text: str) -> str:
    """The template without its guidance. Its comments are whole lines, so dropping them is safe."""
    return "".join(line for line in text.splitlines(keepends=True) if line.strip() and not line.lstrip().startswith("#"))


def scalar(value: str) -> str:
    """A value as YAML text: plain when it reads back unchanged, otherwise single-quoted."""
    try:
        if yaml.safe_load(f"key: {value}") == {"key": value}:
            return value
    except yaml.YAMLError:
        pass
    return "'" + value.replace("'", "''") + "'"


def set_line(text: str, key: str, value: str) -> str:
    """Replace the value of a top-level key."""
    return re.sub(rf"^{key}: .*$", lambda _: f"{key}: {value}", text, count=1, flags=re.MULTILINE)


def set_logsource(text: str, logsource: dict[str, str]) -> str:
    lines = "".join(f"    {key}: {scalar(value)}\n" for key, value in logsources.ordered(logsource).items())
    return LOGSOURCE_KEYS.sub(lambda match: match.group(1) + lines, text, count=1)


def render(
    template: str,
    title: str | None = None,
    author: str | None = None,
    logsource: dict[str, str] | None = None,
    today: datetime.date | None = None,
    rule_id: str | None = None,
    derived_from: str | None = None,
) -> str:
    """The new rule's text: the template without comments, with the mechanical fields filled in.

    With derived_from, `related` names the upstream rule and `license` stays; without it,
    both go, since an original rule has neither.
    """
    text = strip_comments(template)
    if derived_from:
        text = text.replace("<UUID of the related rule>", derived_from)
    else:
        text = LICENSE_LINE.sub("", RELATED_BLOCK.sub("", text, count=1), count=1)
    text = set_line(text, "id", rule_id or str(uuid.uuid4()))
    text = set_line(text, "date", (today or datetime.date.today()).isoformat())
    if title:
        text = set_line(text, "title", scalar(title))
    if author:
        text = set_line(text, "author", scalar(author))
    if logsource:
        text = set_logsource(text, logsource)
    return text


def leftover(text: str) -> list[str]:
    return list(dict.fromkeys(PLACEHOLDER.findall(text)))


def git_author() -> str | None:
    try:
        name = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True, check=False).stdout.strip()
    except OSError:
        return None
    return name or None


def problems(rule: Path, title: str | None, derived_from: str | None = None) -> list[str]:
    found = []
    if derived_from is not None:
        try:
            uuid.UUID(derived_from)
        except ValueError:
            found.append(f"--derived-from must be the upstream rule's id, a UUID: {derived_from}")
    if not FILE_NAME.fullmatch(rule.name):
        found.append("the file name must be lowercase a-z, 0-9 and _ with a .yml extension")
    if rule.exists():
        found.append(f"{rule} already exists")
    if title is not None and (not title.strip() or "".join(title.splitlines()) != title):
        found.append("the title must be one non-empty line")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Start a new Sigma rule from templates/rule.yml.")
    parser.add_argument("rule", type=Path, help="the new rule file, e.g. rules/windows/process_creation/proc_creation_win_example.yml")
    parser.add_argument("--title", help="the rule's title (Title Case, wording matching its level)")
    parser.add_argument("--author", help="public name or handle (default: git config user.name)")
    parser.add_argument("--derived-from", metavar="UUID", help="the id of the rule this one is adapted from, such as a SigmaHQ rule; keeps `related` and `license`")
    source = parser.add_argument_group("logsource", "set these when the rule's folder doesn't follow SigmaHQ's layout")
    source.add_argument("--category", help="e.g. process_creation")
    source.add_argument("--product", help="e.g. windows, azure")
    source.add_argument("--service", help="e.g. security, signinlogs")
    args = parser.parse_args(argv)

    found = problems(args.rule, args.title, args.derived_from)
    if found:
        for problem in found:
            print(f"error: {problem}", file=sys.stderr)
        return 1

    flags = {"category": args.category, "product": args.product, "service": args.service}
    logsource = {key: value for key, value in flags.items() if value} or logsources.from_path(args.rule)
    text = render(TEMPLATE.read_text(encoding="utf-8"), args.title, args.author or git_author(), logsource, derived_from=args.derived_from and str(uuid.UUID(args.derived_from)))

    args.rule.parent.mkdir(parents=True, exist_ok=True)
    args.rule.write_text(text, encoding="utf-8", newline="\n")

    print(f"Created {args.rule.as_posix()}")
    if logsource:
        print("Logsource: " + ", ".join(f"{key} {value}" for key, value in logsources.ordered(logsource).items()))
    else:
        print("Logsource: not set. The folder doesn't follow SigmaHQ's layout; use --category, --product or --service.")
    print("\nStill to fill in (templates/rule.yml explains each one):")
    for placeholder in leftover(text):
        print(f"    {placeholder}")
    if args.derived_from:
        print("\nKeep `license: DRL-1.1` only if the upstream rule is SigmaHQ's, and list its authors first in `author`.")
    print(
        "\nDelete `simulation` if you have no Atomic Red Team test. Then check the rule:"
        f"\n    python {shown(Path(__file__).parent / 'check_rule.py')} {args.rule.as_posix()}"
    )
    return 0


def shown(path: Path) -> str:
    """A path relative to the current directory when it's inside it, for printing."""
    try:
        return path.resolve().relative_to(Path.cwd()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


if __name__ == "__main__":
    sys.exit(main())
