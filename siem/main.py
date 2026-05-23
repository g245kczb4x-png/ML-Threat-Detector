from fastapi import FastAPI, WebSocket, Request
from .engine import ThreatClassifier
import json

app = FastAPI()
model = ThreatClassifier()
active_connections = []

@app.post("/telemetry")
async def receive_telemetry(request: Request):
    data = await request.json()
    command = data.get("command", "")
    
    # 1. Run Classification
    tactic, confidence = model.predict_command(command)
    
    # 2. Prepare the Alert Payload for the Dashboard
    alert = {
        "timestamp": data.get("timestamp"),
        "attacker_ip": data.get("attacker_ip"),
        "command": command,
        "tactic": tactic,
        "confidence": confidence
    }

    # 3. BROADCAST to Next.js Dashboard
    for connection in active_connections:
        await connection.send_text(json.dumps(alert))

    # 4. ACTIVE DEFENSE LOGIC
    # If the ML model is highly confident (e.g. > 85%), tell the agent to KILL
    action = "ALLOW"
    if confidence >= 85:
        action = "BLOCK"
        print(f"[!] CRITICAL THREAT DETECTED: {tactic} ({confidence}%). Sending Kill Signal.")

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