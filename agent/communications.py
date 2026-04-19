# agent/communications.py
import requests
import time
import hmac
import hashlib
import json
import binascii
from agent.config import BASE_URL, SECRET
from agent.security import decrypt_payload, encrypt_payload

# AES Key derived from SECRET (same as in mock agent)
AES_KEY = binascii.unhexlify(SECRET)

# Using a session to persist connections (as in the mock agent)
session = requests.Session()


# -----------------------------
# SECURITY HELPERS (FIXED)
# -----------------------------
def sign_payload(secret, timestamp, body):
    """
    MUST MATCH SERVER EXACTLY:
    f"{timestamp}:{canonical_json}"
    """
    canonical = json.dumps(body or {}, sort_keys=True, separators=(",", ":"))
    msg = f"{timestamp}:{canonical}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def headers(payload=None):
    timestamp = str(int(time.time()))
    signature = sign_payload(SECRET, timestamp, payload or {})
    return {
        "X-AGENT-SECRET": SECRET,
        "X-AGENT-TIMESTAMP": timestamp,
        "X-AGENT-SIGNATURE": signature,
        "Content-Type": "application/json",
    }


# -----------------------------
# 1. AGENT STATUS (Get status from the server)
# -----------------------------
def agent_status():
    """
    Request the status of the agent from the server.
    """
    url = f"{BASE_URL}/api/agent/status/"

    try:
        response = session.get(url, headers=headers({}))

        if response.status_code == 200:
            # Parse the JSON response
            status = response.json()
            return status
        else:
            return {}

    except requests.exceptions.RequestException as e:
        return {}


# -----------------------------
# 2. PULL TASKS (With Decryption and Parsing)
# -----------------------------
def pull_tasks():
    """
    Pulls the tasks from the server, decrypts the payload if necessary,
    and returns a list of tasks.
    """
    url = f"{BASE_URL}/api/tasks/pull/"

    try:
        response = session.get(url, headers=headers({}))

        if response.status_code == 200:
            # Parse the JSON response
            resp = response.json()
            # Check for encrypted payload
            if "payload" in resp:
                encrypted_payload = resp["payload"]
                data = decrypt_payload(AES_KEY, encrypted_payload)
            else:
                # Fallback: non-encrypted response (for development)
                data = resp

            return data.get("tasks", [])
        else:
            return []

    except requests.exceptions.RequestException as e:
        print(f"[TASK PULL] Request Exception: {e}")
        return []


# -----------------------------
# 3. REPORT TASK (ENCRYPTED + SIGNED)
# -----------------------------
def report_task(task_id, results):
    """
    Report the results of a completed task to the server.
    Encrypt the payload and sign the request.
    Returns server JSON response or None on failure.
    """
    url = f"{BASE_URL}/api/tasks/report/"

    # 1. Build plaintext payload
    payload = {"task_id": task_id, "results": results}

    # 2. Encrypt the payload
    encrypted_body = encrypt_payload(AES_KEY, payload)

    # 3. Sign payload
    timestamp = str(int(time.time()))
    signature = sign_payload(SECRET, timestamp, payload)

    # 4. Headers
    headers_dict = headers(payload)
    headers_dict["X-AGENT-BODY"] = encrypted_body

    # 5. Send request
    response = session.post(url, headers=headers_dict)


    try:
        data = response.json()
        return data   # ✅ IMPORTANT FIX
    except Exception:
        return None   # ✅ important safety fallback

# -----------------------------
# 4. INFORM SERVER
# -----------------------------
def inform_server():
    """
    Inform the server that the agent is still alive.
    """
    url = f"{BASE_URL}/api/agent/inform/"
    response = session.post(url, headers=headers())