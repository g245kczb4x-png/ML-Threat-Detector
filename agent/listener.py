import socket
import requests
import datetime

# Configuration
SIEM_URL = "http://127.0.0.1:8000/telemetry"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 8022

def start_agent():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(5)
    print(f"[*] ACTIVE DEFENSE AGENT ONLINE ON PORT {LISTEN_PORT}")

    while True:
        client, addr = server.accept()
        print(f"[+] Attacker connected from {addr[0]}")
        client.send(b"ubuntu@decoy-system:~$ ")

        try:
            while True:
                data = client.recv(1024).decode().strip()
                if not data: break

                # Send to SIEM for analysis
                payload = {
                    "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
                    "attacker_ip": addr[0],
                    "command": data
                }

                try:
                    response = requests.post(SIEM_URL, json=payload)
                    result = response.json()

                    # Check for Kill Signal
                    if result.get("action") == "BLOCK":
                        client.send(b"\r\n[!] SECURITY POLICY VIOLATION: SESSION TERMINATED\r\n")
                        print(f"[!] KILLED SESSION for {addr[0]} due to high-confidence threat.")
                        client.close()
                        break 
                    else:
                        client.send(b"bash: command execution restricted by admin\r\n")
                        client.send(b"ubuntu@decoy-system:~$ ")

                except Exception as e:
                    print(f"[-] SIEM Communication Error: {e}")
                    client.send(b"ubuntu@decoy-system:~$ ")

        except ConnectionResetError:
            pass

if __name__ == "__main__":
    start_agent()