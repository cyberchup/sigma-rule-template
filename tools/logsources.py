"""The logsource a rule needs, worked out from where it sits in SigmaHQ's folder layout.

SigmaHQ files a rule under a folder that names its telemetry, for example
rules/windows/process_creation/ or rules/cloud/azure/signin_logs/. The folder names don't
always match the logsource values (signin_logs is service signinlogs), so the less obvious
ones are listed here, taken from the SigmaHQ repository (rules folder, commit 088855f).
"""

from __future__ import annotations

from pathlib import PurePath

# The top-level folders of SigmaHQ's rules tree. The layout is read from the first of these
# in a path, so the rule can sit under rules/, rules-threat-hunting/ or any other root.
TOP_FOLDERS = ("windows", "linux", "macos", "cloud", "network", "web", "application")

# Telemetry categories that sit in a folder of the same name under windows/, linux/ or
# macos/, possibly one level down (windows/file/file_event/, windows/registry/registry_set/).
CATEGORIES = frozenset({
    "create_remote_thread", "create_stream_hash", "dns_query", "driver_load", "file_access",
    "file_change", "file_delete", "file_event", "file_executable_detected", "file_rename",
    "image_load", "network_connection", "pipe_created", "process_access", "process_creation",
    "process_tampering", "raw_access_thread", "registry_add", "registry_delete",
    "registry_event", "registry_set", "wmi_event",
})

# Folders whose logsource can't be read from the folder name. The longest matching prefix
# wins, so windows/builtin/system/service_control_manager/ is service system.
FOLDERS: dict[str, dict[str, str]] = {
    "windows/powershell/powershell_module": {"category": "ps_module", "product": "windows"},
    "windows/powershell/powershell_script": {"category": "ps_script", "product": "windows"},
    **{
        f"windows/builtin/{folder}": {"product": "windows", "service": service}
        for folder, service in {
            "application": "application",
            "applocker": "applocker",
            "appmodel_runtime": "appmodel-runtime",
            "appxdeployment_server": "appxdeployment-server",
            "appxpackaging_om": "appxpackaging-om",
            "bits_client": "bits-client",
            "capi2": "capi2",
            "certificate_services_client_lifecycle_system": "certificateservicesclient-lifecycle-system",
            "code_integrity": "codeintegrity-operational",
            "diagnosis": "diagnosis-scripted",
            "dns_client": "dns-client",
            "dns_server": "dns-server",
            "driverframeworks": "driver-framework",
            "firewall_as": "firewall-as",
            "iis-configuration": "iis-configuration",
            "ldap": "ldap",
            "lsa_server": "lsa-server",
            "msexchange": "msexchange-management",
            "ntlm": "ntlm",
            "openssh": "openssh",
            "security": "security",
            "security_mitigations": "security-mitigations",
            "servicebus": "microsoft-servicebus-client",
            "shell_core": "shell-core",
            "smbclient": "smbclient-security",
            "smbserver": "smbserver-connectivity",
            "system": "system",
            "taskscheduler": "taskscheduler",
            "terminalservices": "terminalservices-localsessionmanager",
            "windefend": "windefend",
            "wmi": "wmi",
        }.items()
    },
    "linux/auditd": {"product": "linux", "service": "auditd"},
    "cloud/aws/cloudtrail": {"product": "aws", "service": "cloudtrail"},
    "cloud/azure/activity_logs": {"product": "azure", "service": "activitylogs"},
    "cloud/azure/audit_logs": {"product": "azure", "service": "auditlogs"},
    "cloud/azure/identity_protection": {"product": "azure", "service": "riskdetection"},
    "cloud/azure/privileged_identity_management": {"product": "azure", "service": "pim"},
    "cloud/azure/signin_logs": {"product": "azure", "service": "signinlogs"},
    "cloud/gcp/audit": {"product": "gcp", "service": "gcp.audit"},
    "cloud/gcp/gworkspace/admin": {"product": "gcp", "service": "google_workspace.admin"},
    "cloud/gcp/gworkspace/login": {"product": "gcp", "service": "google_workspace.login"},
    "cloud/m365/audit": {"product": "m365", "service": "audit"},
    "cloud/m365/exchange": {"product": "m365", "service": "exchange"},
    "cloud/m365/threat_detection": {"product": "m365", "service": "threat_detection"},
    "cloud/m365/threat_management": {"product": "m365", "service": "threat_management"},
    "application/github/audit": {"product": "github", "service": "audit"},
    "application/bitbucket/audit": {"product": "bitbucket", "service": "audit"},
    "network/dns": {"category": "dns"},
    "network/firewall": {"category": "firewall"},
    "web/proxy_generic": {"category": "proxy"},
    "web/webserver_generic": {"category": "webserver"},
}

# The order SigmaHQ writes logsource keys in.
KEY_ORDER = ("category", "product", "service")


def from_path(rule: PurePath) -> dict[str, str]:
    """The logsource for a rule file's folder, or {} when the folder doesn't say."""
    folders = rule.parent.parts
    start = next((i for i, part in enumerate(folders) if part in TOP_FOLDERS), None)
    if start is None:
        return {}
    folders = folders[start:]
    for end in range(len(folders), 0, -1):
        known = FOLDERS.get("/".join(folders[:end]))
        if known:
            return dict(known)
    if folders[0] == "linux" and len(folders) == 3 and folders[1] == "builtin":
        return {"product": "linux", "service": folders[2]}
    if folders[0] in ("windows", "linux", "macos") and folders[-1] in CATEGORIES and len(folders) <= 3:
        return {"category": folders[-1], "product": folders[0]}
    return {}


def ordered(logsource: dict[str, str]) -> dict[str, str]:
    return {key: logsource[key] for key in KEY_ORDER if logsource.get(key)}
