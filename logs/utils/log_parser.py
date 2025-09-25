import re
import json
from datetime import datetime
from django.utils import timezone  # Add this import

# Correct import from patterns
from .patterns import THREAT_PATTERNS, LOG_FORMATS, SEVERITY_MAP

class LogParser:
    def __init__(self):
        self.common_patterns = [
            # Common log formats in healthcare systems
            (LOG_FORMATS['standard'], self.parse_standard_format),
            (LOG_FORMATS['syslog'], self.parse_syslog_format),
            (LOG_FORMATS['json_log'], self.parse_json_format),
        ]

    def parse_standard_format(self, match, line):
        timestamp_str, level, message = match.groups()
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            # Make datetime timezone-aware
            timestamp = timezone.make_aware(timestamp)
        except ValueError:
            timestamp = timezone.now()  # Use timezone-aware now()

        # Map severity levels
        severity = SEVERITY_MAP.get(level.lower(), 'low')

        return {
            'timestamp': timestamp,
            'level': level.lower(),
            'severity': severity,
            'message': message
        }

    def parse_syslog_format(self, match, line):
        try:
            month_day, time, hostname, message = match.groups()
            # Create a proper datetime object (simplified)
            current_year = datetime.now().year
            timestamp_str = f"{current_year} {month_day} {time}"
            timestamp = datetime.strptime(timestamp_str, '%Y %b %d %H:%M:%S')
            # Make datetime timezone-aware
            timestamp = timezone.make_aware(timestamp)
        except (ValueError, AttributeError):
            timestamp = timezone.now()  # Use timezone-aware now()
            hostname = 'unknown'
            message = line

        return {
            'timestamp': timestamp,
            'level': 'unknown',
            'severity': 'low',
            'message': message,
            'hostname': hostname
        }

    def parse_simple_format(self, match, line):
        timestamp_str, level, message = match.groups()
        try:
            timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            # Make datetime timezone-aware
            timestamp = timezone.make_aware(timestamp)
        except ValueError:
            timestamp = timezone.now()  # Use timezone-aware now()

        # Map severity levels
        severity = SEVERITY_MAP.get(level.lower(), 'low')

        return {
            'timestamp': timestamp,
            'level': level.lower(),
            'severity': severity,
            'message': message
        }

    def parse_json_format(self, match, line):
        # Implementation for JSON format
        try:
            log_data = json.loads(line)
            timestamp_str = log_data.get('timestamp', '')
            if timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                # Make datetime timezone-aware
                timestamp = timezone.make_aware(timestamp)
            else:
                timestamp = timezone.now()  # Use timezone-aware now()

            return {
                'timestamp': timestamp,
                'level': log_data.get('level', 'unknown'),
                'severity': SEVERITY_MAP.get(log_data.get('level', 'unknown').lower(), 'low'),
                'message': log_data.get('message', ''),
                'raw_data': log_data
            }
        except (json.JSONDecodeError, ValueError):
            return self.parse_unknown_format(line)

    def parse_unknown_format(self, line):
        return {
            'timestamp': timezone.now(),  # Use timezone-aware now()
            'level': 'unknown',
            'severity': 'low',
            'message': line
        }

    def parse_line(self, line):
        line = line.strip()
        if not line:
            return None

        for pattern, parser in self.common_patterns:
            match = re.match(pattern, line)
            if match:
                return parser(match, line)
        return self.parse_unknown_format(line)

    def detect_threats(self, log_data):
        threats = []
        for pattern_name, pattern_data in THREAT_PATTERNS.items():
            if re.search(pattern_data['pattern'], log_data['message'], re.IGNORECASE):
                threats.append({
                    'pattern': pattern_name,
                    'severity': pattern_data['severity'],
                    'description': pattern_data['description']
                })

        # Add time-based threat detection
        threats.extend(self.detect_time_based_threats(log_data))

        return threats

    def detect_time_based_threats(self, log_data):
        threats = []
        timestamp = log_data['timestamp']

        # Check for after-hours access (8 PM to 6 AM)
        if timestamp.hour >= 20 or timestamp.hour < 6:
            threats.append({
                'pattern': 'after_hours_access',
                'severity': 'medium',
                'description': 'Access during non-business hours detected'
            })

        # Check for weekend access
        if timestamp.weekday() >= 5:  # 5 = Saturday, 6 = Sunday
            threats.append({
                'pattern': 'weekend_access',
                'severity': 'medium',
                'description': 'Access during weekend detected'
            })

        return threats
