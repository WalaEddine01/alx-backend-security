from celery import shared_task
from django.utils.timezone import now, timedelta
from ip_tracking.models import RequestLog, SuspiciousIP
from django.db import models

@shared_task
def detect_suspicious_ips():
    one_hour_ago = now() - timedelta(hours=1)

    # IPs with more than 100 requests in last hour
    ip_hits = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago)
        .values('ip_address')
        .annotate(count=models.Count('id'))
        .filter(count__gt=100)
    )

    for entry in ip_hits:
        SuspiciousIP.objects.get_or_create(
            ip_address=entry['ip_address'],
            reason="Excessive requests (>100/hour)"
        )

    # IPs accessing sensitive paths
    sensitive_paths = ['/admin', '/login']
    flagged = (
        RequestLog.objects.filter(timestamp__gte=one_hour_ago, path__in=sensitive_paths)
        .values_list('ip_address', flat=True)
        .distinct()
    )

    for ip in flagged:
        SuspiciousIP.objects.get_or_create(
            ip_address=ip,
            reason="Accessed sensitive path (/admin or /login)"
        )
