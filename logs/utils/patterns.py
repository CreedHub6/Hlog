# logs/utils/patterns.py

# Predefined threat patterns for healthcare systems
THREAT_PATTERNS = {
    'unauthorized_access': {
        'pattern': r'(failed login|invalid credential|access denied|authentication failure)',
        'severity': 'high',
        'description': 'Possible unauthorized access attempt'
    },
    'phi_access': {
        'pattern': r'(patient record|medical history|phi|ephi|health information|medical record)',
        'severity': 'critical',
        'description': 'Access to protected health information detected'
    },
    'data_export': {
        'pattern': r'(export|download|bulk data|mass retrieval|data dump)',
        'severity': 'medium',
        'description': 'Large data export operation detected'
    },
    'config_change': {
        'pattern': r'(configuration change|settings modified|user added|permission changed|admin rights)',
        'severity': 'high',
        'description': 'System configuration changes detected'
    },
    'multiple_failures': {
        'pattern': r'(multiple failed|repeated attempt|too many attempts)',
        'severity': 'high',
        'description': 'Multiple failed access attempts from same source'
    },
    'privilege_escalation': {
        'pattern': r'(privilege escalation|root access|admin access|sudo command)',
        'severity': 'critical',
        'description': 'Privilege escalation attempt detected'
    },
    'sql_injection': {
        'pattern': r'(select.*from|union.*select|drop table|insert into|sql syntax)',
        'severity': 'critical',
        'description': 'Possible SQL injection attempt'
    },
    'file_access': {
        'pattern': r'(etc/passwd|/etc/shadow|/root/|/admin/|config\.)',
        'severity': 'high',
        'description': 'Sensitive file access attempt'
    },
    'system_shutdown': {
        'pattern': r'(shutdown|reboot|halt|poweroff|system stop)',
        'severity': 'medium',
        'description': 'System shutdown/reboot command executed'
    },
    'firewall_change': {
        'pattern': r'(iptables|firewall|port open|port forward|ufw)',
        'severity': 'high',
        'description': 'Firewall configuration change detected'
    },
    # Add time-based patterns (these would need special handling)
    'after_hours_access': {
        'pattern': r'.*',  # This will be handled by time-based logic
        'severity': 'medium',
        'description': 'Access during non-business hours'
    },
    'weekend_access': {
        'pattern': r'.*',  # This will be handled by day-based logic
        'severity': 'medium',
        'description': 'Access during weekend hours'
    }
}

# Common log format patterns
LOG_FORMATS = {
    'standard': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - (.*)',
    'syslog': r'(\w+ \d{2} \d{2}:\d{2}:\d{2}) (\w+) (.*)',
    'apache_common': r'(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+)\s*(\S*)" (\d{3}) (\S+)',
    'apache_combined': r'(\S+) (\S+) (\S+) \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+)\s*(\S*)" (\d{3}) (\S+) "([^"]*)" "([^"]*)"',
    'json_log': r'\{.*\}',
}

# Severity mapping
SEVERITY_MAP = {
    'emerg': 'critical',
    'alert': 'critical',
    'crit': 'critical',
    'error': 'high',
    'err': 'high',
    'warning': 'medium',
    'warn': 'medium',
    'notice': 'low',
    'info': 'low',
    'debug': 'low',
    'unknown': 'low'
}
