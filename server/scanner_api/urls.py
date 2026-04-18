from django.urls import path

from .views import (
    agent_status,
    agent_inform,
    tasks_pull,
    task_report,
    create_agent,
    create_task,
    list_agents,
    agent_detail,
)

urlpatterns = [
    # Agent API (machine)
    path("api/agent/status/", agent_status),
    path("api/agent/inform/", agent_inform),

    # Task execution API (machine)
    path("api/tasks/pull/", tasks_pull),
    path("api/tasks/report/", task_report),

    # Admin API (human)
    path("api/admin/create-agent/", create_agent),
    path("api/admin/create-task/", create_task),

    # 🔍 Control panel (your new endpoints)
    path("api/admin/agents/", list_agents, name="list_agents"),
    path("api/admin/agents/<uuid:agent_id>/", agent_detail, name="agent_detail"),
]