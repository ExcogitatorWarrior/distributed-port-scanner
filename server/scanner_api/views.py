import uuid
import secrets
from .utils import is_valid_ip, validate_ports
from django.shortcuts import render
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.admin.views.decorators import staff_member_required
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from .models import Agent, Task, TaskItem, AutoTask
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

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    name = data.get("name")
    contract_interval_seconds = data.get("contract_interval_seconds", 3600)

    if not name:
        return JsonResponse({"error": "missing name"}, status=400)

    try:
        contract_interval_seconds = int(contract_interval_seconds)
    except ValueError:
        return JsonResponse({"error": "invalid interval"}, status=400)

    if contract_interval_seconds < 10:
        return JsonResponse({"error": "interval too small"}, status=400)

    if contract_interval_seconds > 86400:
        return JsonResponse({"error": "interval too large"}, status=400)

    # 1. Создаем самого агента
    agent = Agent.objects.create(
        name=name,
        secret_key=secrets.token_hex(32),
        contract_interval_seconds=contract_interval_seconds
    )

    # 2. Магия автозадач: Ищем все активные шаблоны
    auto_tasks = AutoTask.objects.filter(is_active=True)
    
    created_tasks_count = 0
    for template in auto_tasks:
        Task.objects.create(
            name=f"[AUTO] {template.name}", # Пометка, что создано автоматически
            agent=agent,
            targets_raw=template.targets_raw,
            ports=template.ports,
            schedule=template.schedule,
            is_active=True
        )
        created_tasks_count += 1

    # 3. Возвращаем ответ (добавил инфо о созданных задачах для отладки)
    return JsonResponse({
        "id": str(agent.id),
        "name": agent.name,
        "secret_key": agent.secret_key,
        "contract_interval_seconds": agent.contract_interval_seconds,
        "auto_tasks_applied": created_tasks_count 
    })


@staff_member_required
def create_task(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        # Parsing and validating the data
        data = json.loads(request.body)  # Parse JSON body

        name = data.get("name")
        agent_id = data.get("agent_id")
        targets = data.get("targets", [])
        ports_raw = data.get("ports", [])
        schedule = data.get("schedule", "daily")

        if not name:
            return JsonResponse({"error": "missing name"}, status=400)

        # Check that targets is a list of valid IP addresses
        if not all(is_valid_ip(ip) for ip in targets):
            return JsonResponse({"error": "Invalid IP address format."}, status=400)

        # Validate ports, expecting a list of strings or numbers
        if not isinstance(ports_raw, list):
            return JsonResponse({"error": "Ports should be a list."}, status=400)

        # Make sure the ports are in a correct format (strings or integers)
        ports = validate_ports([str(port) for port in ports_raw])  # Convert all ports to strings for validation
        if not ports:
            return JsonResponse({"error": "Invalid port(s) format."}, status=400)

        agent = None
        if agent_id:
            try:
                agent = Agent.objects.get(id=agent_id, is_active=True)
            except Agent.DoesNotExist:
                return JsonResponse({"error": "invalid agent"}, status=400)

        # Create the task
        task = Task.objects.create(
            name=name,
            agent=agent,
            targets_raw=targets,
            ports=ports,
            schedule=schedule  # Default to daily
        )

        return JsonResponse({
            "task_id": task.id,
            "status": "created"
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

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

@staff_member_required
def admin_ui_agents(request):
    return render(request, "admin_ui/agents_list.html")

@staff_member_required
def agent_detail_page(request, agent_id):
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

    # Passing agent and task data to the frontend template
    return render(request, 'admin_ui/agent_detail.html', {
        'agent': agent,
        'tasks': task_data
    })


@staff_member_required  # This ensures only staff members can access this view
@csrf_exempt  # If you are not using CSRF tokens for this part, you can remove this if needed
def update_allowed_ports(request, task_item_id):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        # Parse the incoming JSON data
        data = json.loads(request.body)

        # Get the allowed_ports from the request data
        allowed_ports = data.get("allowed_ports", None)

        # Validate the allowed_ports field
        if not isinstance(allowed_ports, list) or not all(isinstance(port, int) for port in allowed_ports):
            return JsonResponse({"error": "Invalid allowed ports format. Expected a list of integers."}, status=400)

        # Get the TaskItem object
        task_item = get_object_or_404(TaskItem, id=task_item_id)

        # Update the allowed ports for the TaskItem
        task_item.allowed_ports = allowed_ports

        # Recompute the task status based on found_ports and allowed_ports
        found_ports = task_item.found_ports  # Assuming found_ports is already populated

        # Check compliance and update status accordingly
        if is_compliant(found_ports, allowed_ports):
            task_item.status = "done"
        else:
            task_item.status = "alert"

        task_item.save()

        return JsonResponse({"status": "success", "message": "Allowed ports and status updated successfully"})

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)


@staff_member_required
def delete_agent(request):
    if request.method != "POST":
        return JsonResponse({"error": "POST only"}, status=405)

    try:
        data = json.loads(request.body.decode("utf-8"))
    except Exception:
        return JsonResponse({"error": "invalid JSON"}, status=400)

    agent_id = data.get("id")

    if not agent_id:
        return JsonResponse({"error": "missing id"}, status=400)

    try:
        # Пытаемся найти агента, если UUID невалидный или не найден - кидаем ошибку
        agent = Agent.objects.get(id=agent_id)
    except (Agent.DoesNotExist, ValueError, ValidationError):
        return JsonResponse({"error": "agent not found"}, status=404)

    agent_name = agent.name
    agent.delete()

    return JsonResponse({
        "status": "success",
        "id": str(agent_id),
        "name": agent_name
    })

@staff_member_required
def manage_auto_tasks(request):
    """
    Эндпоинт для создания и получения списка автозадач.
    """
    if request.method == "GET":
        auto_tasks = AutoTask.objects.all().values()
        return JsonResponse(list(auto_tasks), safe=False)

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            
            name = data.get("name")
            targets = data.get("targets", [])
            ports_raw = data.get("ports", [])
            schedule = data.get("schedule", "once")

            if not name:
                return JsonResponse({"error": "missing name"}, status=400)

            # Твоя валидация IP
            if not all(is_valid_ip(ip) for ip in targets):
                return JsonResponse({"error": "Invalid IP address format."}, status=400)

            # Твоя валидация портов
            ports = validate_ports([str(port) for port in ports_raw])
            if not ports:
                return JsonResponse({"error": "Invalid port(s) format."}, status=400)

            # Создаем шаблон
            auto_task = AutoTask.objects.create(
                name=name,
                targets_raw=targets,
                ports=ports,
                schedule=schedule,
                is_active=True
            )

            return JsonResponse({
                "auto_task_id": auto_task.id,
                "status": "created"
            }, status=201)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)