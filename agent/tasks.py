import json
import os
import time

DB_PATH = "tasks_db.json"

def load_tasks():
    if not os.path.exists(DB_PATH):
        return []

    try:
        with open(DB_PATH, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return []

def save_tasks(tasks):
    with open(DB_PATH, "w") as f:
        json.dump(tasks, f, indent=2)

def upsert_task(new_task):
    tasks = load_tasks()

    for task in tasks:
        if task["task_id"] == new_task["task_id"]:
            task.update(new_task)
            save_tasks(tasks)
            return tasks

    tasks.append(new_task)
    save_tasks(tasks)
    return tasks

def update_task(task_id, **updates):
    tasks = load_tasks()

    for task in tasks:
        if task["task_id"] == task_id:
            task.update(updates)
            break

    save_tasks(tasks)
    return tasks

def remove_task(task_id):
    tasks = load_tasks()
    tasks = [t for t in tasks if t["task_id"] != task_id]
    save_tasks(tasks)
    return tasks

def get_pending_tasks():
    tasks = load_tasks()
    return [t for t in tasks if t.get("task_status") != "done"]

def get_delivery_tasks():
    tasks = load_tasks()
    return [t for t in tasks if t.get("task_status") == "delivery"]

def normalize_server_task(task):
    return {
        "task_id": task["task_id"],
        "name": task.get("name"),
        "targets": task.get("targets", []),
        "ports": task.get("ports", []),

        # execution state
        "results": [],
        "task_status": "running",
        "next_parse_date": time.time()
    }

def _create_empty_db():
    with open(DB_PATH, "w") as f:
        json.dump([], f, indent=2)

def ensure_db():
    """
    Ensures the task database file exists and is valid JSON.
    If not, creates a fresh empty structure.
    """

    if not os.path.exists(DB_PATH):
        _create_empty_db()
        return

    # check corruption safety
    try:
        with open(DB_PATH, "r") as f:
            json.load(f)
    except Exception:
        # corrupted file → reset safely
        _create_empty_db()

def should_skip_task(task_id):
    """
    Returns True if task should be skipped based on DB state.
    """

    db_tasks = load_tasks()

    for db_task in db_tasks:
        if db_task["task_id"] != task_id:
            continue

        if db_task.get("task_status") == "done":
            next_time = db_task.get("next_parse_date", 0)

            if time.time() < next_time:
                return True  # still valid cooldown → skip

    return False