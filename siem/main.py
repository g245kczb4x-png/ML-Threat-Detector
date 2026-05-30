import re
import json
import time
import hashlib
import datetime
import io
import os
import numpy as np
from collections import defaultdict
from sklearn.cluster import DBSCAN
from sklearn.metrics.pairwise import cosine_similarity

from fastapi import FastAPI, WebSocket, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

try:
    from .engine import COMMAND_TO_TECHNIQUE, ThreatClassifier
except ImportError:
    from engine import COMMAND_TO_TECHNIQUE, ThreatClassifier

# ── App setup ─────────────────────────────────────────────────────────────────
app   = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

model = ThreatClassifier(
    bert_path  = "./bert_security_model",
    mitre_path = "./mitre_attack.json"
)

active_connections = []

# ── Session tracking ──────────────────────────────────────────────────────────
SESSION_TIMEOUT      = 300
INTRUSION_THRESHOLD  = 3

session_store = defaultdict(lambda: {
    "commands":   [],
    "tactics":    [],
    "first_seen": None,
    "last_seen":  None,
    "blocked":    False,
    "identity":   {}
})

# ── BERT-based fingerprint store ──────────────────────────────────────────────
# Each entry: { "ip": str, "embedding": np.ndarray (768,), "timestamp": float }
embedding_store = []

# Identity db keyed by fingerprint hash
# { hash: { "embedding": np.ndarray, "ips": [...], "first_seen": float, "last_seen": float, "seen_count": int } }
attacker_db = {}

SIMILARITY_THRESHOLD = 0.92   # cosine similarity to flag returning attacker
DBSCAN_EPS           = 0.25   # distance threshold in embedding space
DBSCAN_MIN_SAMPLES   = 2      # min sessions to form a cluster

def embedding_hash(embedding: np.ndarray) -> str:
    bucketed = [round(float(v) * 100) for v in embedding[:32]]
    return hashlib.md5(str(bucketed).encode()).hexdigest()[:12]


def match_or_create_identity(ip: str, embedding: np.ndarray) -> dict:
    """Compare session embedding against known identities using cosine similarity."""
    if len(attacker_db) == 0:
        identity_id = embedding_hash(embedding)
        attacker_db[identity_id] = {
            "embedding":  embedding,
            "ips":        [ip],
            "first_seen": time.time(),
            "last_seen":  time.time(),
            "seen_count": 1
        }
        return {
            "is_returning": False,
            "identity_id":  identity_id,
            "confidence":   0.0,
            "seen_count":   1
        }

    vec       = embedding.reshape(1, -1)
    best_sim  = 0.0
    best_id   = None

    for identity_id, identity in attacker_db.items():
        known = identity["embedding"].reshape(1, -1)
        sim   = cosine_similarity(vec, known)[0][0]
        if sim > best_sim:
            best_sim = sim
            best_id  = identity_id

    if best_sim >= SIMILARITY_THRESHOLD and best_id:
        identity = attacker_db[best_id]
        identity["ips"].append(ip)
        identity["last_seen"]  = time.time()
        identity["seen_count"] += 1
        identity["embedding"] = (identity["embedding"] + embedding) / 2
        return {
            "is_returning": True,
            "identity_id":  best_id,
            "confidence":   round(float(best_sim) * 100, 1),
            "seen_count":   identity["seen_count"]
        }
    else:
        identity_id = embedding_hash(embedding)
        attacker_db[identity_id] = {
            "embedding":  embedding,
            "ips":        [ip],
            "first_seen": time.time(),
            "last_seen":  time.time(),
            "seen_count": 1
        }
        return {
            "is_returning": False,
            "identity_id":  identity_id,
            "confidence":   0.0,
            "seen_count":   1
        }


def run_clustering() -> dict:
    """DBSCAN on BERT session embeddings in 768-dim space."""
    if len(embedding_store) < 2:
        return {
            "clusters":       {},
            "outliers":       [],
            "total_vectors":  len(embedding_store),
            "total_clusters": 0
        }

    vectors = np.array([e["embedding"] for e in embedding_store])
    db      = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMPLES, metric="cosine")
    labels  = db.fit_predict(vectors)

    clusters = {}
    outliers = []

    for i, label in enumerate(labels):
        entry = {
            "ip":        embedding_store[i]["ip"],
            "timestamp": embedding_store[i]["timestamp"]
        }
        if label == -1:
            outliers.append(entry)
        else:
            cluster_id = f"CLUSTER_{label:03d}"
            clusters.setdefault(cluster_id, []).append(entry)

    return {
        "clusters":       clusters,
        "outliers":       outliers,
        "total_vectors":  len(embedding_store),
        "total_clusters": len(clusters)
    }


def update_session(ip: str, alert: dict) -> dict:
    now     = time.time()
    session = session_store[ip]

    if session["last_seen"] and (now - session["last_seen"]) > SESSION_TIMEOUT:
        session_store[ip] = {
            "commands":   [],
            "tactics":    [],
            "first_seen": None,
            "last_seen":  None,
            "blocked":    False,
            "identity":   {}
        }
        session = session_store[ip]

    if session["first_seen"] is None:
        session["first_seen"] = now
    session["last_seen"] = now

    if alert["verdict"] == "MALICIOUS":
        session["commands"].append(alert["command"])
        session["tactics"].append(alert["tactic"])

    malicious_count = len(session["commands"])
    is_intrusion    = malicious_count >= INTRUSION_THRESHOLD
    unique_tactics  = list(dict.fromkeys(session["tactics"]))
    kill_chain      = " → ".join(unique_tactics) if unique_tactics else None

    identity_info   = session.get("identity", {
        "is_returning": False,
        "identity_id":  None,
        "confidence":   0.0,
        "seen_count":   1
    })

    if malicious_count >= INTRUSION_THRESHOLD:
        embedding = model.get_session_embedding(session["commands"])
        embedding_store.append({
            "ip":        ip,
            "embedding": embedding,
            "timestamp": now
        })
        identity_info          = match_or_create_identity(ip, embedding)
        session["identity"] = identity_info

    return {
        "malicious_count":  malicious_count,
        "is_intrusion":     is_intrusion,
        "kill_chain":       kill_chain,
        "session_duration": int(now - session["first_seen"]) if session["first_seen"] else 0,
        "identity":         identity_info
    }

@app.post("/telemetry")
async def receive_telemetry(request: Request):
    data    = await request.json()
    command = data.get("command", "")
    ip      = data.get("attacker_ip", "unknown")

    result  = model.analyze(command)

    alert = {
        "timestamp":    data.get("timestamp"),
        "attacker_ip":  ip,
        "command":      command,
        "verdict":      result["verdict"],
        "tactic":       result["tactic"],
        "technique_id": result["technique_id"],
        "confidence":   int(result["confidence"] * 100),
        "explanation":  result["explanation"],
        "mitigations":  result["mitigations"],
    }

    session_info             = update_session(ip, alert)
    alert["malicious_count"] = session_info["malicious_count"]
    alert["is_intrusion"]    = session_info["is_intrusion"]
    alert["kill_chain"]      = session_info["kill_chain"]
    alert["session_duration"] = session_info["session_duration"]
    alert["identity"]        = session_info["identity"]

    if session_info["is_intrusion"]:
        print(f"[!!] ACTIVE INTRUSION from {ip} — {session_info['kill_chain']}")

    for connection in active_connections:
        await connection.send_text(json.dumps(alert))

    action = "BLOCK" if result["kill"] else "ALLOW"
    if result["kill"]:
        print(f"[!] KILL: {result['tactic']} — {result['technique_id']} ({alert['confidence']}%)")

    return {"status": "processed", "action": action, "alert": alert}

@app.get("/sessions")
async def get_sessions():
    result = []
    for ip, session in session_store.items():
        if not session["commands"]:
            continue
        unique_tactics = list(dict.fromkeys(session["tactics"]))
        result.append({
            "ip":              ip,
            "commands":        session["commands"],
            "tactics":         session["tactics"],
            "first_seen":      session["first_seen"],
            "last_seen":       session["last_seen"],
            "malicious_count": len(session["commands"]),
            "kill_chain":      " → ".join(unique_tactics),
            "identity":        session.get("identity", {})
        })
    return result

@app.get("/fingerprints")
async def get_fingerprints():
    result = []
    for identity_id, identity in attacker_db.items():
        result.append({
            "identity_id":  identity_id,
            "seen_count":   identity["seen_count"],
            "ips_seen":     list(set(identity["ips"])),
            "first_seen":   identity["first_seen"],
            "last_seen":    identity["last_seen"],
            "is_recurring": identity["seen_count"] > 1
        })
    return sorted(result, key=lambda x: x["seen_count"], reverse=True)

@app.get("/clusters")
async def get_clusters():
    result            = run_clustering()
    enriched_clusters = []

    for cluster_id, members in result["clusters"].items():
        ips = list(set(m["ip"] for m in members))
        enriched_clusters.append({
            "cluster_id":   cluster_id,
            "size":         len(members),
            "ips":          ips,
            "first_seen":   min(m["timestamp"] for m in members),
            "last_seen":    max(m["timestamp"] for m in members),
            "is_recurring": len(set(m["ip"] for m in members)) > 1
        })

    return {
        "clusters":       sorted(enriched_clusters, key=lambda x: x["size"], reverse=True),
        "outliers":       result["outliers"],
        "total_vectors":  result["total_vectors"],
        "total_clusters": result["total_clusters"]
    }

@app.get("/report")
async def generate_report():
    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(
        buffer, pagesize=letter,
        rightMargin=0.75*inch, leftMargin=0.75*inch,
        topMargin=0.75*inch,   bottomMargin=0.75*inch
    )

    styles = getSampleStyleSheet()
    elements = []

    title_style = ParagraphStyle(
        "title", fontSize=20, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#ffffff"),
        backColor=colors.HexColor("#09090b"),
        alignment=TA_CENTER, spaceAfter=6, spaceBefore=6, borderPad=12
    )
    sub_style = ParagraphStyle(
        "sub", fontSize=9, fontName="Helvetica",
        textColor=colors.HexColor("#71717a"),
        alignment=TA_CENTER, spaceAfter=20
    )
    heading_style = ParagraphStyle(
        "heading", fontSize=11, fontName="Helvetica-Bold",
        textColor=colors.HexColor("#e4e4e7"),
        spaceBefore=16, spaceAfter=6
    )
    body_style = ParagraphStyle(
        "body", fontSize=8, fontName="Helvetica",
        textColor=colors.HexColor("#a1a1aa"),
        spaceAfter=4, leading=12
    )

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph("INCIDENT REPORT", title_style))
    elements.append(Paragraph(f"Agentic Deception Platform — Generated {now}", sub_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#27272a")))
    elements.append(Spacer(1, 16))

    total_alerts   = sum(len(s["commands"]) for s in session_store.values())
    total_sessions = len([s for s in session_store.values() if s["commands"]])
    intrusions     = len([s for s in session_store.values() if len(s["commands"]) >= INTRUSION_THRESHOLD])
    returning      = len([i for i in attacker_db.values() if i["seen_count"] > 1])

    elements.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    summary_data = [
        ["Total Sessions",       str(total_sessions)],
        ["Malicious Commands",   str(total_alerts)],
        ["Active Intrusions",    str(intrusions)],
        ["Returning Attackers",  str(returning)],
        ["Behavioral Clusters",  str(len(attacker_db))],
        ["Report Generated",     now],
    ]
    summary_table = Table(summary_data, colWidths=[2.5*inch, 4*inch])
    summary_table.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#18181b")),
        ("TEXTCOLOR",     (0,0), (0,-1),  colors.HexColor("#71717a")),
        ("TEXTCOLOR",     (1,0), (1,-1),  colors.HexColor("#e4e4e7")),
        ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#18181b"), colors.HexColor("#09090b")]),
        ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#27272a")),
        ("TOPPADDING",    (0,0), (-1,-1), 6),
        ("BOTTOMPADDING", (0,0), (-1,-1), 6),
        ("LEFTPADDING",   (0,0), (-1,-1), 10),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 16))

    for ip, session in session_store.items():
        if not session["commands"]:
            continue

        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#27272a")))
        elements.append(Spacer(1, 8))

        unique_tactics = list(dict.fromkeys(session["tactics"]))
        kill_chain     = " → ".join(unique_tactics) if unique_tactics else "N/A"
        is_intrusion   = len(session["commands"]) >= INTRUSION_THRESHOLD
        identity       = session.get("identity", {})

        elements.append(Paragraph(
            f"SESSION: {ip} {'— ⚠ ACTIVE INTRUSION' if is_intrusion else '— SUSPICIOUS'}",
            heading_style
        ))

        meta_data = [
            ["Attacker IP",        ip],
            ["First Seen",         datetime.datetime.fromtimestamp(session["first_seen"]).strftime("%H:%M:%S") if session["first_seen"] else "—"],
            ["Last Seen",          datetime.datetime.fromtimestamp(session["last_seen"]).strftime("%H:%M:%S") if session["last_seen"] else "—"],
            ["Kill Chain",         kill_chain],
            ["Malicious Commands", str(len(session["commands"]))],
            ["Identity ID",        identity.get("identity_id", "—")],
            ["Returning Attacker", "YES" if identity.get("is_returning") else "NO"],
            ["Match Confidence",   f"{identity.get('confidence', 0)}%" if identity.get("is_returning") else "—"],
        ]
        meta_table = Table(meta_data, colWidths=[2.5*inch, 4*inch])
        meta_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#18181b")),
            ("TEXTCOLOR",     (0,0), (0,-1),  colors.HexColor("#71717a")),
            ("TEXTCOLOR",     (1,0), (1,-1),  colors.HexColor("#e4e4e7")),
            ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#18181b"), colors.HexColor("#09090b")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#27272a")),
            ("TOPPADDING",    (0,0), (-1,-1), 6),
            ("BOTTOMPADDING", (0,0), (-1,-1), 6),
            ("LEFTPADDING",   (0,0), (-1,-1), 10),
        ]))
        elements.append(meta_table)
        elements.append(Spacer(1, 10))

        elements.append(Paragraph("INTERCEPTED COMMANDS", ParagraphStyle(
            "small_heading", fontSize=8, fontName="Helvetica-Bold",
            textColor=colors.HexColor("#71717a"), spaceAfter=4
        )))
        cmd_rows = [["#", "Command", "Tactic"]]
        for j, (cmd, tactic) in enumerate(zip(session["commands"], session["tactics"])):
            cmd_rows.append([
                str(j + 1),
                cmd[:80] + ("..." if len(cmd) > 80 else ""),
                tactic.replace("_", " ")
            ])
        cmd_table = Table(cmd_rows, colWidths=[0.3*inch, 4.5*inch, 1.7*inch])
        cmd_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#27272a")),
            ("TEXTCOLOR",     (0,0), (-1,0),  colors.HexColor("#71717a")),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 7),
            ("TEXTCOLOR",     (1,1), (1,-1),  colors.HexColor("#34d399")),
            ("FONTNAME",      (1,1), (1,-1),  "Courier"),
            ("TEXTCOLOR",     (0,1), (0,-1),  colors.HexColor("#71717a")),
            ("TEXTCOLOR",     (2,1), (2,-1),  colors.HexColor("#a1a1aa")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.HexColor("#18181b"), colors.HexColor("#09090b")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#27272a")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        elements.append(cmd_table)
        elements.append(Spacer(1, 8))

        seen_techniques = set()
        mits = []
        for cmd in session["commands"]:
            for pattern, technique_id in COMMAND_TO_TECHNIQUE:
                if re.search(pattern, cmd.lower()) and technique_id not in seen_techniques:
                    tech = model.mitre_index.get(technique_id)
                    if tech and tech["mitigations"]:
                        seen_techniques.add(technique_id)
                        mits.append((technique_id, tech["name"], tech["mitigations"][0][:200]))

        if mits:
            elements.append(Paragraph("RECOMMENDED MITIGATIONS", ParagraphStyle(
                "small_heading", fontSize=8, fontName="Helvetica-Bold",
                textColor=colors.HexColor("#71717a"), spaceAfter=4
            )))
            for technique_id, name, mit in mits:
                elements.append(Paragraph(
                    f"<b>{technique_id} — {name}</b>",
                    ParagraphStyle("mit_head", fontSize=8, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor("#e4e4e7"), spaceAfter=2)
                ))
                elements.append(Paragraph(mit, body_style))

    if attacker_db:
        elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#27272a")))
        elements.append(Spacer(1, 8))
        elements.append(Paragraph("ATTACKER BEHAVIORAL FINGERPRINTS", heading_style))
        fp_rows = [["Identity ID", "Sessions", "IPs Observed", "Returning", "First Seen", "Last Seen"]]
        for identity_id, identity in attacker_db.items():
            fp_rows.append([
                identity_id,
                str(identity["seen_count"]),
                ", ".join(set(identity["ips"]))[:30],
                "YES" if identity["seen_count"] > 1 else "NO",
                datetime.datetime.fromtimestamp(identity["first_seen"]).strftime("%H:%M:%S"),
                datetime.datetime.fromtimestamp(identity["last_seen"]).strftime("%H:%M:%S"),
            ])
        fp_table = Table(fp_rows, colWidths=[1.3*inch, 0.7*inch, 1.7*inch, 0.7*inch, 0.9*inch, 0.9*inch])
        fp_table.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#27272a")),
            ("TEXTCOLOR",     (0,0), (-1,0),  colors.HexColor("#71717a")),
            ("FONTNAME",      (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 7),
            ("TEXTCOLOR",     (0,1), (0,-1),  colors.HexColor("#a78bfa")),
            ("FONTNAME",      (0,1), (0,-1),  "Courier"),
            ("TEXTCOLOR",     (1,1), (-1,-1), colors.HexColor("#a1a1aa")),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [colors.HexColor("#18181b"), colors.HexColor("#09090b")]),
            ("GRID",          (0,0), (-1,-1), 0.5, colors.HexColor("#27272a")),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ]))
        elements.append(fp_table)

    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#27272a")))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(
        "Generated by Agentic Deception Platform — ML-Threat-Detector",
        ParagraphStyle("footer", fontSize=7, fontName="Helvetica",
                       textColor=colors.HexColor("#52525b"), alignment=TA_CENTER)
    ))

    doc.build(elements)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=incident_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"}
    )

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        active_connections.remove(websocket)
