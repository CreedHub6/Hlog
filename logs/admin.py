from django.contrib import admin
from .models import LogSource, LogEntry, ThreatPattern, Alert

@admin.register(LogSource)
class LogSourceAdmin(admin.ModelAdmin):
    list_display = ('name', 'source_type', 'is_active', 'created_at')
    list_filter = ('source_type', 'is_active', 'created_at')
    search_fields = ('name', 'description')
    list_editable = ('is_active',)
    ordering = ('-created_at',)

@admin.register(LogEntry)
class LogEntryAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'source', 'severity', 'created_at')
    list_filter = ('severity', 'source', 'timestamp', 'created_at')
    search_fields = ('raw_message', 'parsed_data')
    readonly_fields = ('created_at',)
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'

@admin.register(ThreatPattern)
class ThreatPatternAdmin(admin.ModelAdmin):
    list_display = ('name', 'severity', 'is_active', 'created_at')
    list_filter = ('severity', 'is_active', 'created_at')
    search_fields = ('name', 'description', 'pattern')
    list_editable = ('is_active', 'severity')
    ordering = ('-created_at',)

@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ('pattern', 'log_entry', 'is_resolved', 'created_at')
    list_filter = ('is_resolved', 'pattern', 'created_at')
    search_fields = ('description', 'pattern__name')
    readonly_fields = ('created_at', 'resolved_at')
    ordering = ('-created_at',)
    actions = ['mark_as_resolved', 'mark_as_unresolved']

    def mark_as_resolved(self, request, queryset):
        updated = queryset.update(is_resolved=True)
        self.message_user(request, f"{updated} alerts marked as resolved.")
    mark_as_resolved.short_description = "Mark selected alerts as resolved"

    def mark_as_unresolved(self, request, queryset):
        updated = queryset.update(is_resolved=False)
        self.message_user(request, f"{updated} alerts marked as unresolved.")
    mark_as_unresolved.short_description = "Mark selected alerts as unresolved"
