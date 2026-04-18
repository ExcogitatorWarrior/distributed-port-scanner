import uuid
import secrets
from django.shortcuts import render
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from .models import Agent, Task, TaskItem
from .services import is_compliant
from .security import (
    verify_request,
    decrypt_payload,
    encrypt_payload
)
import binascii
import json

def agent_status(request):
    # =========================================================
    # 1. Extract headers
    # =========================================================
    secret = request.headers.get("X-AGENT-SECRET")
    timestamp = request.headers.get("X-AGENT-TIMESTAMP")
    signature = request.headers.get("X-AGENT-SIGNATURE")

    if not secret:
        return JsonResponse({"error": "missing secret"}, status=401)

    # =========================================================
    # 2. Validate agent identity
    # =========================================================
    try:
        agent = Agent.objects.get(secret_key=secret, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse({"error": "invalid agent"}, status=403)

    # =========================================================
    # 3. Verify request integrity (HMAC + replay protection)
    #    For this endpoint body is empty -> {}
    # =========================================================
    if not verify_request(secret, timestamp, {}, signature):
        return JsonResponse({"error": "invalid signature"}, status=403)

    # =========================================================
    # 4. Update heartbeat
    # =========================================================
    agent.last_contact_at = timezone.now()
    agent.last_seen_ip = request.META.get("REMOTE_ADDR")
    agent.save(update_fields=["last_contact_at", "last_seen_ip"])

    # =========================================================
    # 5. Response (keep simple for now)
    # =========================================================
    return JsonResponse({
        "status": "ok",
        "agent_id": str(agent.id),
        "contract_interval_seconds": agent.contract_interval_seconds,
    })

def tasks_pull(request):
    # =========================================================
    # 1. Extract headers
    # =========================================================
    secret = request.headers.get("X-AGENT-SECRET")
    timestamp = request.headers.get("X-AGENT-TIMESTAMP")
    signature = request.headers.get("X-AGENT-SIGNATURE")

    if not secret:
        return JsonResponse({"error": "missing secret"}, status=401)

    # =========================================================
    # 2. Authenticate agent
    # =========================================================
    try:
        agent = Agent.objects.get(secret_key=secret, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse({"error": "invalid agent"}, status=403)

    # =========================================================
    # 3. Verify request integrity (HMAC + replay protection)
    # =========================================================
    if not verify_request(secret, timestamp, {}, signature):
        return JsonResponse({"error": "invalid signature"}, status=403)

    # =========================================================
    # 4. Fetch tasks
    # =========================================================
    tasks = Task.objects.filter(agent=agent, is_active=True)

    tasks_data = []

    for task in tasks:
        tasks_data.append({
            "task_id": task.id,
            "name": task.name,
            "targets": task.targets_raw,
            "ports": task.ports,
            "schedule": task.schedule,
        })

    # =========================================================
    # 5. FIXED ENCRYPTION KEY (32 bytes AES-256)
    # =========================================================
    try:
        encryption_key = binascii.unhexlify(agent.secret_key)
    except Exception:
        return JsonResponse({"error": "invalid encryption key format"}, status=500)

    # =========================================================
    # 6. Encrypt payload
    # =========================================================
    encrypted_payload = encrypt_payload(
        key=encryption_key,
        data={"tasks": tasks_data}
    )

    # =========================================================
    # 7. Return secure response
    # =========================================================
    return JsonResponse({
        "status": "ok",
        "payload": encrypted_payload
    })

@csrf_exempt
def task_report(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    # =========================================================
    # 1. Extract headers
    # =========================================================
    secret = request.headers.get("X-AGENT-SECRET")
    timestamp = request.headers.get("X-AGENT-TIMESTAMP")
    signature = request.headers.get("X-AGENT-SIGNATURE")
    encrypted_body = request.headers.get("X-AGENT-BODY")

    if not secret:
        return JsonResponse({"error": "missing secret"}, status=401)

    # =========================================================
    # 2. Validate agent
    # =========================================================
    try:
        agent = Agent.objects.get(secret_key=secret, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse({"error": "invalid agent"}, status=403)

    # =========================================================
    # 3. Decrypt payload (FIXED KEY DERIVATION)
    # =========================================================
    try:
        payload = decrypt_payload(
            key=binascii.unhexlify(agent.secret_key),
            token=encrypted_body
        )
    except Exception:
        return JsonResponse({"error": "decryption failed"}, status=403)

    # =========================================================
    # 4. Verify request integrity AFTER decrypt
    # =========================================================
    if not verify_request(secret, timestamp, payload, signature):
        return JsonResponse({"error": "invalid signature"}, status=403)

    # =========================================================
    # 5. Extract data
    # =========================================================
    task_id = payload.get("task_id")
    results = payload.get("results", [])

    try:
        task = Task.objects.get(id=task_id, agent=agent)
    except Task.DoesNotExist:
        return JsonResponse({"error": "task not found"}, status=404)

    updated = 0

    # =========================================================
    # 6. Process TaskItems (auto-create safe path)
    # =========================================================
    for item in results:
        ip = item.get("ip")
        found_ports = item.get("found_ports", [])

        task_item, created = TaskItem.objects.get_or_create(
            task=task,
            ip_address=ip,
            defaults={
                "agent": agent,
                "allowed_ports": [0],  # safe default
                "status": "running",
                "found_ports": [],
            }
        )

        task_item.agent = agent
        task_item.found_ports = found_ports

        allowed = task_item.allowed_ports or [0]

        if is_compliant(found_ports, allowed):
            task_item.status = "done"
        else:
            task_item.status = "alert"

        task_item.save()
        updated += 1

    # =========================================================
    # 7. Update task metadata
    # =========================================================
    task.last_result_received_at = timezone.now()
    task.save(update_fields=["last_result_received_at"])

    return JsonResponse({
        "status": "ok",
        "updated_items": updated
    })

@csrf_exempt
def agent_inform(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    # =========================================================
    # 1. Extract headers
    # =========================================================
    secret = request.headers.get("X-AGENT-SECRET")
    timestamp = request.headers.get("X-AGENT-TIMESTAMP")
    signature = request.headers.get("X-AGENT-SIGNATURE")

    if not secret:
        return JsonResponse({"error": "missing secret"}, status=401)

    # =========================================================
    # 2. Authenticate agent
    # =========================================================
    try:
        agent = Agent.objects.get(secret_key=secret, is_active=True)
    except Agent.DoesNotExist:
        return JsonResponse({"error": "invalid agent"}, status=403)

    # =========================================================
    # 3. Verify request integrity (empty body)
    # =========================================================
    if not verify_request(secret, timestamp, {}, signature):
        return JsonResponse({"error": "invalid signature"}, status=403)

    # =========================================================
    # 4. State transition: pending → running
    # =========================================================
    task_items = TaskItem.objects.filter(
        agent=agent,
        status="pending"
    )

    updated = task_items.update(status="running")

    # =========================================================
    # 5. Response
    # =========================================================
    return JsonResponse({
        "status": "ok",
        "updated_items": updated
    })

@staff_member_required
def create_agent(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    name = request.POST.get("name")

    if not name:
        return JsonResponse({"error": "missing name"}, status=400)

    agent = Agent.objects.create(
        name=name,
        secret_key=secrets.token_hex(32)  # auto-generate secure key
    )

    return JsonResponse({
        "id": str(agent.id),
        "name": agent.name,
        "secret_key": agent.secret_key
    })

@staff_member_required
def create_task(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    data = json.loads(request.body)

    name = data.get("name")
    agent_id = data.get("agent_id")

    if not name:
        return JsonResponse({"error": "missing name"}, status=400)

    agent = None
    if agent_id:
        try:
            agent = Agent.objects.get(id=agent_id, is_active=True)
        except Agent.DoesNotExist:
            return JsonResponse({"error": "invalid agent"}, status=400)

    task = Task.objects.create(
        name=name,
        agent=agent,
        targets_raw=data.get("targets", []),
        ports=data.get("ports", []),
        schedule=data.get("schedule", "once"),
    )

    return JsonResponse({
        "task_id": task.id,
        "status": "created"
    })

@staff_member_required
def list_agents(request):
    agents = Agent.objects.all()

    data = [
        {
            "id": str(a.id),
            "name": a.name,
            "last_seen": a.last_seen,
            "last_contact_at": a.last_contact_at,
            "is_active": a.is_active,
            "secret_key": a.secret_key,
        }
        for a in agents
    ]

    return JsonResponse({"agents": data})

@staff_member_required
def agent_detail(request, agent_id):
    agent = get_object_or_404(Agent, id=agent_id)

    tasks = agent.tasks.all()

    task_data = []
    for t in tasks:
        task_data.append({
            "id": t.id,
            "name": t.name,
            "targets": t.targets_raw,
            "ports": t.ports,
            "schedule": t.schedule,
            "is_active": t.is_active,
            "last_result_received_at": t.last_result_received_at,
            "items": [
                {
                    "id": i.id,
                    "ip": i.ip_address,
                    "status": i.status,
                    "found_ports": i.found_ports,
                    "allowed_ports": i.allowed_ports,
                }
                for i in t.items.all()
            ]
        })

    return JsonResponse({
        "agent": {
            "id": str(agent.id),
            "name": agent.name,
            "last_seen": agent.last_seen,
            "last_contact_at": agent.last_contact_at,
            "tasks": task_data
        }
    })