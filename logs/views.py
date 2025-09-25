from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from django.contrib import messages
from datetime import datetime
from .models import LogSource, LogEntry, Alert, ThreatPattern
from .utils.log_parser import LogParser
import json



def dashboard(request):
    # Get statistics for dashboard
    total_logs = LogEntry.objects.count()
    high_severity = LogEntry.objects.filter(severity='high').count()
    critical_alerts = Alert.objects.filter(log_entry__severity='critical', is_resolved=False).count()

    # Get recent alerts
    recent_alerts = Alert.objects.filter(is_resolved=False).order_by('-created_at')[:10]

    # Get data for the chart
    severity_data = {
        'low': LogEntry.objects.filter(severity='low').count(),
        'medium': LogEntry.objects.filter(severity='medium').count(),
        'high': LogEntry.objects.filter(severity='high').count(),
        'critical': LogEntry.objects.filter(severity='critical').count(),
    }

    context = {
        'total_logs': total_logs,
        'high_severity': high_severity,
        'critical_alerts': critical_alerts,
        'recent_alerts': recent_alerts,
        'severity_data': severity_data,  # Add this to context
    }
    return render(request, 'dashboard.html', context)

def upload_logs(request):
    if request.method == 'POST' and request.FILES.get('log_file'):
        log_file = request.FILES['log_file']
        source_id = request.POST.get('source')

        # Check if source was selected
        if not source_id:
            messages.error(request, "Please select a log source.")
            sources = LogSource.objects.filter(is_active=True)
            return render(request, 'upload.html', {'sources': sources})

        try:
            log_source = LogSource.objects.get(id=source_id)
        except LogSource.DoesNotExist:
            messages.error(request, "Invalid log source selected.")
            sources = LogSource.objects.filter(is_active=True)
            return render(request, 'upload.html', {'sources': sources})

        parser = LogParser()
        line_count = 0
        alert_count = 0

        try:
            # Read the file content properly
            file_content = log_file.read().decode('utf-8')
            lines = file_content.splitlines()

            # Process each line of the log file
            for line in lines:
                decoded_line = line.strip()
                if decoded_line:
                    parsed_data = parser.parse_line(decoded_line)
                    
                    # Skip if parsing failed
                    if not parsed_data:
                        continue
                        
                    line_count += 1

                    # Convert datetime objects to strings for JSON serialization
                    serializable_data = parsed_data.copy()
                    if 'timestamp' in serializable_data:
                        # Store timestamp as ISO string for JSON
                        serializable_data['timestamp'] = parsed_data['timestamp'].isoformat()

                    # Detect threats
                    threats = parser.detect_threats(parsed_data)

                    # Create log entry
                    log_entry = LogEntry.objects.create(
                        source=log_source,
                        raw_message=decoded_line,
                        timestamp=parsed_data['timestamp'],
                        severity=parsed_data.get('severity', 'unknown'),
                        parsed_data=serializable_data
                    )

                    # Create alerts for detected threats
                    for threat in threats:
                        # Get the actual pattern from THREAT_PATTERNS
                        from .utils.patterns import THREAT_PATTERNS
                        pattern_text = THREAT_PATTERNS.get(threat['pattern'], {}).get('pattern', '')
                        
                        pattern, created = ThreatPattern.objects.get_or_create(
                            name=threat['pattern'],
                            defaults={
                                'description': threat['description'],
                                'pattern': pattern_text,
                                'severity': threat['severity']
                            }
                        )

                        Alert.objects.create(
                            log_entry=log_entry,
                            pattern=pattern,
                            description=threat['description']
                        )
                        alert_count += 1

            if line_count == 0:
                messages.warning(request, "No valid log entries found in the file.")
            else:
                messages.success(request, f"Processed {line_count} log entries. Found {alert_count} threats.")

        except UnicodeDecodeError:
            messages.error(request, "Error decoding the file. Please ensure it's a UTF-8 text file.")
        except Exception as e:
            messages.error(request, f"Error processing file: {str(e)}")
        
        return redirect('/')

    # GET request - show upload form
    sources = LogSource.objects.filter(is_active=True)
    return render(request, 'upload.html', {'sources': sources})


def view_alerts(request):
    alerts = Alert.objects.filter(is_resolved=False).order_by('-created_at')
    return render(request, 'alerts.html', {'alerts': alerts})


def resolve_alert(request, alert_id):
    if request.method == 'POST':
        try:
            alert = Alert.objects.get(id=alert_id)
            alert.is_resolved = True
            alert.resolved_by = request.user
            alert.resolved_at = timezone.now()
            alert.save()
            return JsonResponse({'status': 'success'})
        except Alert.DoesNotExist:
            return JsonResponse({'status': 'error', 'message': 'Alert not found'})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method'})


def log_stats(request):
    # Provide data for charts
    severity_data = {
        'low': LogEntry.objects.filter(severity='low').count(),
        'medium': LogEntry.objects.filter(severity='medium').count(),
        'high': LogEntry.objects.filter(severity='high').count(),
        'critical': LogEntry.objects.filter(severity='critical').count(),
    }

    return JsonResponse(severity_data)
