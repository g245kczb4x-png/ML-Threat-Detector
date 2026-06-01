import re
import base64
import json
import torch
import numpy as np
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path

MODEL_PATH = Path(__file__).parent / "securebert"

# ── Preprocessor (mirrors training) ──────────────────────────────────────────
_WRAPPERS     = re.compile(r'/bin/(?:ba)?sh\s+-c\s+|bash\s+-c\s+|eval\s+|exec\s+', re.I)
_MULTI_SPACE  = re.compile(r'\s+')
_B64_EMBEDDED = re.compile(r'[A-Za-z0-9+/=]{20,}')


def _try_b64(tok):
    try:
        dec = base64.b64decode(tok + '=' * (-len(tok) % 4)).decode('utf-8', errors='ignore')
        if dec and all(32 <= ord(c) < 127 or c in '\n\t' for c in dec):
            return dec
    except Exception:
        pass
    return tok


def preprocess(cmd: str) -> str:
    cmd = _WRAPPERS.sub(' ', str(cmd).strip())
    toks = []
    for t in _MULTI_SPACE.split(cmd):
        if len(t) > 16 and re.fullmatch(r'[A-Za-z0-9+/=]+', t):
            toks.append(_try_b64(t))
        else:
            toks.append(_B64_EMBEDDED.sub(lambda m: _try_b64(m.group(0)), t))
    return _MULTI_SPACE.sub(' ', ' '.join(toks)).strip().lower()


# ── MITRE rule labeler (fast deterministic path) ──────────────────────────────
_RULES = [
    (re.compile(
        r'/etc/shadow|/etc/passwd|/etc/security|id_rsa|authorized_keys'
        r'|htpasswd|credential|secret|token|password|gpg.*key'
        r'|mimikatz|lsass|hashdump|john\s|hashcat|unshadow|hydra|medusa',
        re.I), "CREDENTIAL_ACCESS"),
    (re.compile(
        r'sudo[\s$]|sudo$|su\s+-|pkexec|chmod\s+[u+]?s|chown.*root|setuid'
        r'|perm.*4000|perm.*u=s|capsh|getcap|setcap|LD_PRELOAD'
        r'|exploit|cve-|enable\s*$|conf\s*t|escalat'
        r'|chmod.*4[0-9]{3}|find.*-perm.*-4000',
        re.I), "PRIVILEGE_ESCALATION"),
    (re.compile(
        r'crontab|cron\.d|rc\.local|init\.d|systemctl.*enable'
        r'|\.bashrc|\.profile|\.bash_profile|useradd|usermod|adduser'
        r'|chpasswd|visudo|sudoers|sshd_config|PermitRootLogin'
        r'|update-rc\.d|chkconfig|/etc/crontab',
        re.I), "PERSISTENCE"),
    (re.compile(
        r'/dev/tcp|/dev/udp|nc\s|ncat\s|netcat|socat'
        r'|bash\s+-i|python.*socket|perl.*socket'
        r'|mkfifo|msfvenom|meterpreter'
        r'|(curl|wget).*\|.*(bash|sh|python|perl)'
        r'|chmod.*\+x.*/tmp|/tmp/[^\s]+\s*&&'
        r'|wget\s+http|curl\s+http.*-[oO]'
        r'|tftp.*-[gi]|ftpget|busybox.*wget'
        r'|echo.*base64.*-d.*\|.*(bash|sh)',
        re.I), "EXECUTION"),
    (re.compile(
        r'nmap|masscan|ping\s|ping$|traceroute|whois'
        r'|ip\s+addr|ip\s+a$|ifconfig|netstat|ss\s+-|arp\s|arp$'
        r'|uname|hostname|arch|lscpu|dmidecode'
        r'|curl.*ifconfig|curl.*ipinfo|wget.*myip'
        r'|show\s+version|show\s+interface|show\s+ip'
        r'|id$|whoami|w$|who$',
        re.I), "RECONNAISSANCE"),
    (re.compile(
        r'ls[\s/\-]|ls$|find\s|find$|locate\s|whereis|which\s'
        r'|cat\s+/etc/|cat\s+/proc/|cat\s+/var/'
        r'|df\s|df$|free\s|free$|ps\s|ps$|mount|lsblk|top$|htop'
        r'|last\b|lastlog|env$|printenv|set$'
        r'|dpkg\s+-l|rpm\s+-qa|apt\s+list|yum\s+list'
        r'|pwd$|cd\s+/',
        re.I), "DISCOVERY"),
]


def rule_label(cmd: str):
    for pat, tactic in _RULES:
        if pat.search(cmd):
            return tactic
    return None


# ── SecureBERT classifier ─────────────────────────────────────────────────────
class TacticClassifier:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tok    = AutoTokenizer.from_pretrained(str(MODEL_PATH))
        self.model  = AutoModelForSequenceClassification.from_pretrained(
            str(MODEL_PATH)
        ).to(self.device).eval()
        with open(MODEL_PATH / "label_map.json") as f:
            self.id2label = json.load(f)["id2label"]

    def predict(self, command: str) -> dict:
        clean = preprocess(command)

        # Fast path — deterministic rule engine
        rule = rule_label(clean)
        if rule:
            return {"tactic": rule, "confidence": 1.0, "source": "rule"}

        # Slow path — SecureBERT
        inputs = self.tok(
            clean, return_tensors="pt",
            truncation=True, max_length=128
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.no_grad():
            probs = torch.softmax(
                self.model(**inputs).logits, dim=-1
            )[0]
        idx = probs.argmax().item()
        return {
            "tactic":     self.id2label[str(idx)],
            "confidence": round(probs[idx].item(), 4),
            "source":     "model",
        }

    def get_command_embedding(self, cmd: str) -> np.ndarray:
        inputs = self.tok(
            cmd, return_tensors="pt",
            truncation=True, max_length=128
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        with torch.no_grad():
            outputs = self.model.base_model(**inputs)
            embedding = outputs.last_hidden_state[:, 0, :].squeeze().cpu().numpy()
        return embedding

    def get_session_embedding(self, commands: list) -> np.ndarray:
        if not commands:
            return np.zeros(self.model.config.hidden_size)
        embeddings = [self.get_command_embedding(cmd) for cmd in commands]
        return np.mean(embeddings, axis=0)


# Singleton — load once at import time
_classifier = None

def classify(command: str) -> dict:
    global _classifier
    if _classifier is None:
        _classifier = TacticClassifier()
    return _classifier.predict(command)


def get_session_embedding(commands: list) -> np.ndarray:
    global _classifier
    if _classifier is None:
        _classifier = TacticClassifier()
    return _classifier.get_session_embedding(commands)
