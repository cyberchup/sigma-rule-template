"""Check Sigma rules written from templates/rule.yml.

    python tools/check_rule.py rules/windows/process_creation/proc_creation_win_certutil_download.yml
    python tools/check_rule.py rules

For each rule (a .yml file, or every .yml under a folder) it reports:

- any of the template's <placeholders> still in the file;
- anything pySigma can't parse;
- every issue from the installed Sigma validators: pySigma's own and, with
  pySigma-validators-sigmahq installed, SigmaHQ's conventions, including its file naming.
  This is the same set `sigma check` runs with `validators: all`.

Only the template's own placeholders count, so a rule matching a value such as '<script>'
is not flagged. It exits 1 if anything was found, so it can gate CI.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.plugins import InstalledSigmaPlugins
from sigma.validation import SigmaValidator

TEMPLATE = Path(__file__).resolve().parent.parent / "templates" / "rule.yml"
PLACEHOLDER = re.compile(r"<[^<>\n]+>")


def template_placeholders(template: Path = TEMPLATE) -> set[str]:
    text = "".join(line for line in template.read_text(encoding="utf-8").splitlines(keepends=True) if not line.lstrip().startswith("#"))
    return set(PLACEHOLDER.findall(text))


def rule_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        files.extend(sorted(path.rglob("*.yml")) if path.is_dir() else [path])
    return files


def placeholder_problems(files: list[Path], placeholders: set[str]) -> list[str]:
    found = []
    for path in files:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            for placeholder in PLACEHOLDER.findall(line):
                if placeholder in placeholders:
                    found.append(f"{path.as_posix()}:{number}: placeholder left: {placeholder}")
    return found


def sigma_problems(files: list[Path]) -> list[str]:
    """Parse errors, then validator issues for the rules that parsed."""
    found = []
    collection = SigmaCollection.load_ruleset([str(path) for path in files], collect_errors=True)
    parsed = []
    for rule in collection.rules:
        for error in rule.errors:
            found.append(f"{location(rule)}: parse error: {type(error).__name__}: {error}")
        if not rule.errors:
            parsed.append(rule)
    validator = SigmaValidator.from_dict({"validators": ["all"]}, InstalledSigmaPlugins.autodiscover().validators)
    issues = []
    try:
        for rule in parsed:
            issues.extend(validator.validate_rule(rule))
        issues.extend(validator.finalize())
    except RuntimeError as error:
        # pySigma downloads MITRE ATT&CK and D3FEND data on first use to validate tags.
        found.append(f"error: the validators couldn't run: {error}. They need internet access the first time, to cache MITRE data.")
        return found
    for issue in issues:
        for rule in issue.rules:
            found.append(f"{location(rule)}: {issue.severity.name.lower()}: {type(issue).__name__}: {issue.description}")
    return found


def location(rule) -> str:
    source = getattr(rule, "source", None)
    path = getattr(source, "path", None)
    return Path(path).as_posix() if path else str(getattr(rule, "title", "unknown rule"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Sigma rules written from templates/rule.yml.")
    parser.add_argument("paths", nargs="+", type=Path, help="rule files, or folders to search for .yml files")
    args = parser.parse_args(argv)

    missing = [path for path in args.paths if not path.exists()]
    if missing:
        for path in missing:
            print(f"error: {path} doesn't exist", file=sys.stderr)
        return 1
    files = rule_files(args.paths)
    if not files:
        print("No .yml files found.")
        return 0

    found = placeholder_problems(files, template_placeholders()) + sigma_problems(files)
    for problem in found:
        print(problem)
    count = len(files)
    print(f"\n{count} rule{'s' if count != 1 else ''} checked, {len(found)} problem{'s' if len(found) != 1 else ''} found.")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
