"""Tests of the template and the two tools that work with it."""

from __future__ import annotations

import datetime
import re
from pathlib import Path, PurePosixPath

import pytest
import yaml

import check_rule
import logsources
import new_rule

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = (ROOT / "templates" / "rule.yml").read_text(encoding="utf-8")
TODAY = datetime.date(2026, 11, 17)
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
UPSTREAM = "19b08b1c-861d-4e75-a1ef-ea0c1baf202b"
# SigmaHQ's field order, with the optional fields this template uses.
FIELD_ORDER = [
    "title", "id", "related", "status", "description", "license", "references", "author", "date",
    "tags", "logsource", "detection", "falsepositives", "level", "simulation",
]
# What a rule's author writes in place of the placeholders the scaffold leaves.
FILLED = {
    "description": (
        "Detects certutil.exe run with a flag that makes it fetch a URL and an http or https address on the command line.\n"
        "Attackers use the signed binary to download tools and payloads without bringing their own downloader.\n"
    ),
    "references": ["https://lolbas-project.github.io/lolbas/Binaries/Certutil/"],
    "tags": ["attack.command-and-control", "attack.t1105"],
    "logsource": {"category": "process_creation", "product": "windows", "definition": "Requirements: Sysmon EID 1 or Security 4688 with command-line auditing"},
    "detection": {
        "selection_img": [{"Image|endswith": "\\certutil.exe"}, {"OriginalFileName": "CertUtil.exe"}],
        "selection_cli": {"CommandLine|contains": ["urlcache ", "verifyctl "]},
        "selection_http": {"CommandLine|contains": "http"},
        "condition": "all of selection_*",
    },
    "falsepositives": ["Scripts that use certutil to fetch files on hosts without another download tool"],
    "simulation": [{"type": "atomic-red-team", "name": "certutil download (urlcache)", "technique": "T1105", "atomic_guid": "dd3b61dd-7bbc-48cd-ab51-49ad1a776df0"}],
}
RULE = Path("rules/windows/process_creation/proc_creation_win_certutil_download.yml")
TITLE = "Potential File Download Via Certutil.EXE"


def scaffold(tmp_path: Path, monkeypatch, *args: str) -> Path:
    monkeypatch.chdir(tmp_path)
    assert new_rule.main([str(RULE), "--title", TITLE, "--author", "cyberchup", *args]) == 0
    return tmp_path / RULE


def fill(path: Path) -> None:
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule.update(FILLED)
    path.write_text(yaml.safe_dump(rule, sort_keys=False, allow_unicode=True), encoding="utf-8")


# The template


def test_template_is_valid_yaml_in_sigmahq_field_order():
    assert list(yaml.safe_load(TEMPLATE)) == FIELD_ORDER


def test_every_template_placeholder_is_listed_by_check_rule():
    placeholders = check_rule.template_placeholders()
    assert "<random UUIDv4>" in placeholders and "<FieldName>" in placeholders
    # Comment examples aren't placeholders, so a rule may match a value such as '<script>'.
    assert not any(p.startswith("<script") for p in placeholders)


# new_rule.py


def test_render_fills_the_mechanical_fields_and_drops_comments():
    text = new_rule.render(TEMPLATE, TITLE, "cyberchup", {"category": "process_creation", "product": "windows"}, TODAY)
    assert not any(line.lstrip().startswith("#") for line in text.splitlines())
    rule = yaml.safe_load(text)
    assert UUID4.fullmatch(rule["id"])
    assert (rule["title"], rule["author"], rule["date"], rule["status"]) == (TITLE, "cyberchup", TODAY, "experimental")
    assert rule["logsource"] == {"category": "process_creation", "product": "windows", "definition": "Requirements: <telemetry or audit settings the rule needs>"}


def test_each_rule_gets_its_own_id():
    assert yaml.safe_load(new_rule.render(TEMPLATE))["id"] != yaml.safe_load(new_rule.render(TEMPLATE))["id"]


def test_an_original_rule_has_no_related_or_license():
    rule = yaml.safe_load(new_rule.render(TEMPLATE, today=TODAY))
    assert "related" not in rule and "license" not in rule
    assert list(rule) == [field for field in FIELD_ORDER if field not in ("related", "license")]


def test_a_derived_rule_names_its_upstream_and_keeps_the_license():
    rule = yaml.safe_load(new_rule.render(TEMPLATE, today=TODAY, derived_from=UPSTREAM))
    assert rule["related"] == [{"id": UPSTREAM, "type": "derived"}]
    assert rule["license"] == "DRL-1.1"


def test_a_service_logsource_replaces_the_category_line():
    rule = yaml.safe_load(new_rule.render(TEMPLATE, logsource={"service": "signinlogs", "product": "azure"}))
    assert list(rule["logsource"].items())[:2] == [("product", "azure"), ("service", "signinlogs")]
    assert "category" not in rule["logsource"]


@pytest.mark.parametrize("title", ["Potential Abuse: Certutil", "It's #1", "- leading dash"])
def test_titles_that_need_quoting_read_back_unchanged(title):
    assert yaml.safe_load(new_rule.render(TEMPLATE, title=title))["title"] == title


def test_main_writes_the_rule_and_lists_whats_left(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch)
    out = capsys.readouterr().out
    assert "Logsource: category process_creation, product windows" in out
    assert "<public URL>" in out and "<random UUIDv4>" not in out
    assert path.read_text(encoding="utf-8").endswith("\n")


def test_flags_override_the_folder(tmp_path, monkeypatch):
    path = scaffold(tmp_path, monkeypatch, "--product", "okta", "--service", "okta")
    assert yaml.safe_load(path.read_text(encoding="utf-8"))["logsource"]["service"] == "okta"


@pytest.mark.parametrize(
    "args, message",
    [
        (["rules/Bad-Name.yml"], "file name"),
        (["rules/ok.yml", "--title", ""], "title"),
        (["rules/ok.yml", "--derived-from", "not-a-uuid"], "--derived-from"),
    ],
)
def test_main_refuses_bad_input(tmp_path, monkeypatch, capsys, args, message):
    monkeypatch.chdir(tmp_path)
    assert new_rule.main(args) == 1
    assert message in capsys.readouterr().err
    assert not list(tmp_path.rglob("*.yml"))


def test_main_never_overwrites(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch)
    before = path.read_text(encoding="utf-8")
    assert new_rule.main([str(RULE)]) == 1
    assert "already exists" in capsys.readouterr().err
    assert path.read_text(encoding="utf-8") == before


# logsources.py


@pytest.mark.parametrize(
    "folder, expected",
    [
        ("rules/windows/process_creation", {"category": "process_creation", "product": "windows"}),
        ("rules/windows/registry/registry_set", {"category": "registry_set", "product": "windows"}),
        ("rules/windows/powershell/powershell_script", {"category": "ps_script", "product": "windows"}),
        ("rules/windows/builtin/security", {"product": "windows", "service": "security"}),
        ("rules/windows/builtin/system/service_control_manager", {"product": "windows", "service": "system"}),
        ("rules/windows/builtin/code_integrity", {"product": "windows", "service": "codeintegrity-operational"}),
        ("rules/linux/process_creation", {"category": "process_creation", "product": "linux"}),
        ("rules/linux/auditd/execve", {"product": "linux", "service": "auditd"}),
        ("rules/linux/builtin/sshd", {"product": "linux", "service": "sshd"}),
        ("rules/macos/file_event", {"category": "file_event", "product": "macos"}),
        ("rules/cloud/azure/signin_logs", {"product": "azure", "service": "signinlogs"}),
        ("rules/cloud/azure/audit_logs", {"product": "azure", "service": "auditlogs"}),
        ("rules/cloud/aws/cloudtrail", {"product": "aws", "service": "cloudtrail"}),
        ("rules/cloud/m365/threat_management", {"product": "m365", "service": "threat_management"}),
        ("rules-threat-hunting/windows/process_creation", {"category": "process_creation", "product": "windows"}),
        ("windows/process_creation", {"category": "process_creation", "product": "windows"}),
        # Folders that mix logsources, or that SigmaHQ doesn't use, are left to the author.
        ("rules/windows/sysmon", {}),
        ("rules/windows/powershell/powershell_classic", {}),
        ("rules/network/zeek", {}),
        ("rules/windows/mystery", {}),
        ("my_rules", {}),
    ],
)
def test_logsource_from_folder(folder, expected):
    assert logsources.from_path(PurePosixPath(folder) / "rule.yml") == expected


# check_rule.py


def test_a_fresh_scaffold_fails_the_check(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch)
    assert check_rule.main([str(path)]) == 1
    out = capsys.readouterr().out
    assert "placeholder left: <public URL>" in out
    assert "parse error" in out  # <FieldName>|<modifier> isn't a Sigma modifier


def test_a_filled_rule_passes_the_check(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch)
    fill(path)
    assert check_rule.main([str(path)]) == 0, capsys.readouterr().out


def test_a_filled_derived_rule_passes_the_check(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch, "--derived-from", UPSTREAM)
    fill(path)
    assert check_rule.main([str(path)]) == 0, capsys.readouterr().out


def test_sigmahq_validators_run(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch)
    fill(path)
    misnamed = path.with_name("certutil_download.yml")
    path.rename(misnamed)
    assert check_rule.main([str(tmp_path / "rules")]) == 1
    # SigmaHQ wants a Windows process_creation rule's file name to start with proc_creation_win_.
    assert "certutil_download.yml: medium: SigmahqFilenamePrefixIssue" in capsys.readouterr().out


def test_values_that_look_like_placeholders_are_not_flagged(tmp_path, monkeypatch, capsys):
    path = scaffold(tmp_path, monkeypatch)
    fill(path)
    text = path.read_text(encoding="utf-8").replace("'urlcache '", "'<script>'")
    path.write_text(text, encoding="utf-8")
    assert check_rule.main([str(path)]) == 0, capsys.readouterr().out
