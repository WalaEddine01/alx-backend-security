from django.utils.timezone import now
from ip_tracking.models import RequestLog
from ipware import get_client_ip

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip, _ = get_client_ip(request)

        if ip:
            # Check if IP is blacklisted
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Forbidden: Your IP is blocked.")

            # Log request
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=now(),
                path=request.path
            )

        return self.get_response(request)
