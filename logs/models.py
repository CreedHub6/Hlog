from django.db import models
from django.contrib.auth.models import User

class LogSource(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    source_type = models.CharField(max_length=50, choices=[
        ('server', 'Server'),
        ('application', 'Application'),
        ('network', 'Network Device'),
        ('database', 'Database'),
    ])
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class LogEntry(models.Model):
    SEVERITY_LEVELS = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    source = models.ForeignKey(LogSource, on_delete=models.CASCADE)
    raw_message = models.TextField()
    timestamp = models.DateTimeField()
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    parsed_data = models.JSONField(default=dict)  # Store structured log data
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.timestamp} - {self.source} - {self.severity}"

class ThreatPattern(models.Model):
    name = models.CharField(max_length=200)
    description = models.TextField()
    pattern = models.TextField(help_text="Regular expression pattern to match threats")
    severity = models.CharField(max_length=10, choices=LogEntry.SEVERITY_LEVELS)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return self.name

class Alert(models.Model):
    log_entry = models.ForeignKey(LogEntry, on_delete=models.CASCADE)
    pattern = models.ForeignKey(ThreatPattern, on_delete=models.CASCADE)
    description = models.TextField()
    is_resolved = models.BooleanField(default=False)
    resolved_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL)
    resolved_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Alert: {self.pattern.name} - {self.created_at}"
