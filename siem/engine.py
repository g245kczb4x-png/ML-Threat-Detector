import re
import json
import requests
import os

# ── MITRE ATT&CK Playbook ─────────────────────────────────────────────────────
MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

def load_mitre_playbook(path="./mitre_attack.json"):
    if not os.path.exists(path):
        print("Downloading MITRE ATT&CK playbook...")
        r = requests.get(MITRE_URL)
        with open(path, "w") as f:
            json.dump(r.json(), f)
        print("Downloaded.")
    with open(path) as f:
        return json.load(f)


def build_mitre_index(playbook):
    objects = playbook["objects"]
    mitigation_texts = {
        obj["id"]: obj.get("description", "")
        for obj in objects
        if obj["type"] == "course-of-action"
    }
    mitigations_by_technique = {}
    for obj in objects:
        if obj["type"] == "relationship" and obj.get("relationship_type") == "mitigates":
            src = obj["source_ref"]
            tgt = obj["target_ref"]
            if src in mitigation_texts:
                mitigations_by_technique.setdefault(tgt, []).append(mitigation_texts[src])
    index = {}
    for obj in objects:
        if obj["type"] != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        technique_id = next(
            (r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), None
        )
        if not technique_id:
            continue
        tactics = [
            p["phase_name"].replace("-", "_").upper()
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        ]
        index[technique_id] = {
            "name":        obj.get("name", ""),
            "tactics":     tactics,
            "description": obj.get("description", "")[:300],
            "mitigations": mitigations_by_technique.get(obj["id"], [])[:3],
            "stix_id":     obj["id"]
        }
    return index

# ── Command → Technique mapping ───────────────────────────────────────────────
COMMAND_TO_TECHNIQUE = [
    (r"nc\s+-e.*/bin/(ba)?sh",          "T1059.004"),
    (r"nc\s+-lvp",                       "T1059.004"),
    (r"/dev/tcp",                        "T1059.004"),
    (r"socat.*exec.*bash",               "T1059.004"),
    (r"python.*socket.*connect",         "T1059.004"),
    (r"perl.*socket",                    "T1059.004"),
    (r"curl.*\|\s*bash",                 "T1059.004"),
    (r"wget.*\|\s*bash",                 "T1059.004"),
    (r"rm\s+-rf\s+/?",                    "T1485"),
    (r"dd\s+if=/dev/zero",               "T1485"),
    (r"mkfs\.",                          "T1485"),
    (r"shred\s+-u",                      "T1485"),
    (r"cat\s+/etc/shadow",               "T1003.008"),
    (r"cat\s+/etc/passwd",               "T1003.008"),
    (r"unshadow",                        "T1003.008"),
    (r"john\s+--wordlist",               "T1110.002"),
    (r"hashcat",                         "T1110.002"),
    (r"chmod\s+u\+s.*bash",              "T1548.001"),
    (r"chmod\s+\+s.*python",             "T1548.001"),
    (r"chmod\s+777\s+/etc/passwd",       "T1548.001"),
    (r"echo.*root.*>>\s*/etc/passwd",    "T1136.001"),
    (r"sudo\s+su",                       "T1548.003"),
    (r".*>>\s*/etc/crontab",             "T1053.003"),
    (r"crontab\s+-e",                    "T1053.003"),
    (r"useradd.*backdoor",               "T1136.001"),
    (r"echo.*NOPASSWD.*sudoers",         "T1548.003"),
    (r"curl.*--data.*@/etc",             "T1041"),
    (r"scp\s+/etc/(passwd|shadow)",      "T1041"),
    (r"tar.*curl.*evil",                 "T1041"),
    (r"base64.*decode.*bash",            "T1027"),
    (r"base64\s+-d.*bash",               "T1027"),
    (r"history\s+-c",                    "T1070.003"),
    (r"unset\s+HISTFILE",                "T1070.003"),
    (r"chmod\s+000.*log",                "T1070.002"),
    (r"nmap",                            "T1046"),
]

def explain_command(cmd: str, mitre_index: dict):
    cmd_lower = cmd.lower().strip()
    for pattern, technique_id in COMMAND_TO_TECHNIQUE:
        if re.search(pattern, cmd_lower):
            technique = mitre_index.get(technique_id)
            if technique:
                tactic      = technique["tactics"][0] if technique["tactics"] else "EXECUTION"
                explanation = f"{technique['name']} ({technique_id}) — {technique['description'][:150]}"
                mitigations = technique["mitigations"] or ["No specific mitigations found."]
                return tactic, technique_id, explanation, mitigations
    return "EXECUTION", None, "Suspicious command — manual review recommended.", []

