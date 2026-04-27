import time
import json

from communications import (
    pull_tasks,
    agent_status,
    inform_server,
    report_task
)

from config import (
    BASE_URL,
    SECRET,
    CONTACT_INTERVAL_DEFAULT
)

from utils import (
    parse_ports,
    sort_scan_results,
    generate_scan_list,
    compute_next_parse_date
)
from scanner import scan_port
import threading

# fallback: store for later delivery
from tasks import (
    upsert_task,
    ensure_db,
    load_tasks,
    save_tasks,
    should_skip_task
)

# Global variable for the contact interval
CONTACT_INTERVAL = CONTACT_INTERVAL_DEFAULT
TASKS = []
CURRENT_TIME = int(time.time())  # Current time in seconds
NEXT_CALL_TIME = CURRENT_TIME + CONTACT_INTERVAL  # Next time to call in seconds

def update_times():
    global CURRENT_TIME, NEXT_CALL_TIME
    CURRENT_TIME = int(time.time())  # Update the current time
    NEXT_CALL_TIME = CURRENT_TIME + CONTACT_INTERVAL  # Update the next call time

def initial_loop():

    global CONTACT_INTERVAL
    global CURRENT_TIME, NEXT_CALL_TIME

    while True:
        # Issue agent_status and check response
        response = agent_status()

        if response.get("status") == "ok":
            # Update the contact interval from the server's response
            CONTACT_INTERVAL = response.get("contract_interval_seconds", CONTACT_INTERVAL_DEFAULT)
            update_times()
            break  # Exit loop after success

        else:
            time.sleep(CONTACT_INTERVAL_DEFAULT)

def process_delivery_queue(TASKS):
    db_tasks = load_tasks()
    if not db_tasks:
        return

    server_tasks = TASKS
    server_task_ids = {t["task_id"] for t in server_tasks}

    updated_db = []

    for task in db_tasks:
        if task.get("task_status") != "delivery":
            updated_db.append(task)
            continue

        task_id = task["task_id"]

        # if task no longer exists on server → drop it
        if task_id not in server_task_ids:
            continue

        try:

            status = report_task(task_id, task["results"])

            # IMPORTANT: only mark done if server accepted it
            if status.get("status") == "ok":
                task["task_status"] = "done"
            else:
                updated_db.append(task)

        except Exception as e:
            updated_db.append(task)

    save_tasks(updated_db)

def initial_task_request():
    global TASKS
    TASKS = pull_tasks()

def process_and_update_tasks():
    global NEXT_CALL_TIME, TASKS
    global CONTACT_INTERVAL
    # Process the pulled tasks
    for task in TASKS:

        if should_skip_task(task["task_id"]):
            continue

        inform_server()
        CONTINUE_FLAG = False

        # Generate scan list for the task
        scan_list = generate_scan_list(task)
        for entry in scan_list:
            # Parse the list of ports for the entry
            # Convert task['ports'] to a comma-separated string without brackets
            ports = [str(port) for port in task['ports']]  # Convert each port to a string
            ports_str = ",".join(ports)  # Join the ports into a string (e.g., "22,80,443,3389")

            # Now parse the ports correctly
            ports = parse_ports(ports_str)
            entry['found_ports'] = []

            lock = threading.Lock()

            def worker(ip, port):
                port_num, is_open = scan_port(ip, port, 1)
                if is_open:
                    with lock:
                        entry["found_ports"].append(port_num)

            threads = []
            start_port = 0

            for port in ports:
                start_port += 1

                # throttle like original code
                while threading.active_count() > 800:
                    time.sleep(0.05)

                t = threading.Thread(target=worker, args=(entry['ip'], port))
                t.start()
                threads.append(t)

            # join last thread (same "approximate" behavior as original code)
            if threads:
                threads[-1].join()


            # Check if we need to pull new tasks
            if time.time() >= NEXT_CALL_TIME:
                response = agent_status()
                if response.get("status") == "ok":
                    TASKS = pull_tasks()
                    process_delivery_queue(TASKS)
                    # Update NEXT_CALL_TIME
                    CONTACT_INTERVAL = response.get("contract_interval_seconds", CONTACT_INTERVAL_DEFAULT)
                    update_times()

                    # Check if the current task is still in the new TASKS list
                    if not any(existing_task['task_id'] == task['task_id'] for existing_task in TASKS):
                        CONTINUE_FLAG = True
                        break  # Break the loop if the task is no longer present in TASKS

        if CONTINUE_FLAG is True:
            continue

        response = agent_status()
        sorted_scan_list = sort_scan_results(scan_list)
        if response.get("status") == "ok":
            status = report_task(task['task_id'], sorted_scan_list)
            if status.get("status") == "ok":
                upsert_task({
                    "task_id": task["task_id"],
                    "results": None,
                    "task_status": "done",
                    "delivery_status": "delivered",
                    "next_parse_date": compute_next_parse_date(task["schedule"])
                })

        else:

            upsert_task({
                "task_id": task["task_id"],
                "results": sorted_scan_list,
                "task_status": "delivery",
                "next_parse_date": compute_next_parse_date(task["schedule"])
            })

if __name__ == "__main__":
    ensure_db()
    initial_loop()
    initial_task_request()
    while True:
        process_and_update_tasks()
        time.sleep(5)