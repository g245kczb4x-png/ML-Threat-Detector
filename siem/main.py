from fastapi import FastAPI, WebSocket, Request
from .engine import ThreatClassifier
import json

app   = FastAPI()
model = ThreatClassifier(
    bert_path="./bert_security_model",
    mitre_path="./mitre_attack.json"
)
active_connections = []

@app.post("/telemetry")
async def receive_telemetry(request: Request):
    data    = await request.json()
    command = data.get("command", "")

    result = model.analyze(command)

    alert = {
        "timestamp":    data.get("timestamp"),
        "attacker_ip":  data.get("attacker_ip"),
        "command":      command,
        "verdict":      result["verdict"],
        "tactic":       result["tactic"],
        "technique_id": result["technique_id"],
        "confidence":   int(result["confidence"] * 100),
        "explanation":  result["explanation"],
        "mitigations":  result["mitigations"],
    }

    for connection in active_connections:
        await connection.send_text(json.dumps(alert))

    action = "BLOCK" if result["kill"] else "ALLOW"
    if result["kill"]:
        print(f"[!] CRITICAL THREAT: {result['tactic']} — {result['technique_id']} ({alert['confidence']}%) — KILL SIGNAL SENT")

    return {"status": "processed", "action": action}

@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except:
        active_connections.remove(websocket)