from django.db import models
import uuid

class Agent(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    name = models.CharField(max_length=255)

    internal_ip = models.GenericIPAddressField(null=True, blank=True)
    last_seen_ip = models.GenericIPAddressField(null=True, blank=True)

    secret_key = models.CharField(max_length=128, unique=True)

    is_active = models.BooleanField(default=True)

    last_seen = models.DateTimeField(null=True, blank=True)

    # last time we received any request from agent
    last_contact_at = models.DateTimeField(null=True, blank=True)

    # heartbeat / contract interval (in seconds)
    contract_interval_seconds = models.IntegerField(default=3600)

    created_at = models.DateTimeField(auto_now_add=True)

class Task(models.Model):
    name = models.CharField(max_length=255)

    agent = models.ForeignKey(
        "Agent",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="tasks"
    )

    targets_raw = models.JSONField()
    ports = models.JSONField(default=list)

    schedule = models.CharField(max_length=20, default="once")

    is_active = models.BooleanField(default=True)

    last_result_received_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

class TaskItem(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("done", "Done"),
        ("alert", "Alert"),
        ("failed", "Failed"),
    ]

    task = models.ForeignKey(
        "Task",
        on_delete=models.CASCADE,
        related_name="items"
    )

    ip_address = models.GenericIPAddressField()

    agent = models.ForeignKey(
        "Agent",
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )

    # what agent found during scan
    found_ports = models.JSONField(default=list)

    # PER-HOST policy (your design)
    allowed_ports = models.JSONField(default=list)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default="pending"
    )

    created_at = models.DateTimeField(auto_now_add=True)

class AutoTask(models.Model):
    name = models.CharField(max_length=255)

    # Поля agent здесь нет, так как задача "общая"
    
    targets_raw = models.JSONField()
    ports = models.JSONField(default=list)

    # Как часто создаваемая задача должна запускаться у агента
    schedule = models.CharField(max_length=20, default="once")

    # Активен ли сам шаблон автозадачи
    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"AutoTask: {self.name}"