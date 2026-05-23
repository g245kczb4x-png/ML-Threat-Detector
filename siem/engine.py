import os
import re
import base64
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

class ThreatClassifier:
    def __init__(self, csv_path="dataset.csv"):
        self.csv_path = csv_path
        self.pipeline = None
        self._initialize_pipeline()

    def _clean_text(self, text):
        """Collapses spaces and decodes common obfuscation."""
        try:
            if len(text.strip()) > 8 and re.match(r'^[A-Za-z0-9+/=]+$', text.strip()):
                text = base64.b64decode(text).decode('utf-8')
        except: pass
        return re.sub(r'\s+', ' ', text).strip().lower()

    def _augment_data(self, base_commands, tactic):
        """Creates 'noisy' variations of commands to harden the model."""
        noise_flags = ["-v", "--force", "--ignore-errors", "-all", "2>/dev/null", "> /tmp/out", "&& sleep 1"]
        augmented_pairs = []
        for cmd in base_commands:
            augmented_pairs.append((cmd, tactic)) # Original
            for flag in noise_flags:
                augmented_pairs.append((f"{cmd} {flag}", tactic)) # With flag
        return augmented_pairs

    def _generate_robust_baseline_data(self):
        print("[*] Training with Augmented Adversarial Telemetry...")
        
        # Define core threats
        raw_threats = {
            "RECONNAISSANCE": ["nmap -sV", "netstat -antp", "masscan", "ping -c", "arp -a", "ss -lntu"],
            "SYSTEM_DISCOVERY": ["whoami", "id", "uname -a", "cat /etc/os-release", "ps aux", "hostnamectl"],
            "CREDENTIAL_ACCESS": ["cat /etc/shadow", "cat /etc/passwd", "grep -r password", "cat ~/.ssh/id_rsa", "sudo -l"],
            "EXFILTRATION": ["nc -w 3", "scp -r", "curl -X POST", "tar -czf", "wget --post-file"]
        }

        all_data = []
        for tactic, cmds in raw_threats.items():
            all_data.extend(self._augment_data(cmds, tactic))
        
        df = pd.DataFrame(all_data, columns=["command", "tactic"])
        df.to_csv(self.csv_path, index=False)
        return df

    def _initialize_pipeline(self):
        # Always re-generate the augmented baseline for this demo to ensure high accuracy
        df = self._generate_robust_baseline_data()

        X = df["command"].apply(self._clean_text).values
        y = df["tactic"].values

        self.pipeline = Pipeline([
            ('vectorizer', TfidfVectorizer(
                analyzer='char_wb', 
                ngram_range=(2, 5), # Capture 2-5 character chunks
                min_df=1
            )),
            ('classifier', LogisticRegression(
                C=5.0, # Higher C = trust the training data more
                class_weight='balanced',
                max_iter=1000
            ))
        ])

        self.pipeline.fit(X, y)
        print(f"[+] ML V4 Operational. Trained on {len(df)} augmented variations.")

    def predict_command(self, raw_command: str):
        processed = self._clean_text(raw_command)
        if not processed: return "UNKNOWN", 0

        prediction = self.pipeline.predict([processed])[0]
        probs = self.pipeline.predict_proba([processed])[0]
        idx = np.where(self.pipeline.classes_ == prediction)[0][0]
        confidence = int(round(probs[idx] * 100))

        return str(prediction), confidence