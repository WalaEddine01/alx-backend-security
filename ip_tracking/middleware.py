from django.utils.timezone import now
from django.http import HttpResponseForbidden
from django.core.cache import cache
from ipware import get_client_ip
from ipgeolocation import IpGeolocationAPI
from ip_tracking.models import RequestLog, BlockedIP


geo = IpGeolocationAPI()

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip, _ = get_client_ip(request)

        if ip:
            # Blocked IP check
            if BlockedIP.objects.filter(ip_address=ip).exists():
                return HttpResponseForbidden("Forbidden: Your IP is blocked.")

            # Check cache for geolocation
            geo_data = cache.get(f"geo_{ip}")
            if not geo_data:
                try:
                    geo_data = geo.get_geolocation_data(ip_address=ip)
                    cache.set(f"geo_{ip}", geo_data, timeout=86400)  # Cache for 24 hours
                except Exception:
                    geo_data = {}

            country = geo_data.get("country_name", "") if geo_data else ""
            city = geo_data.get("city", "") if geo_data else ""

            # Log request
            RequestLog.objects.create(
                ip_address=ip,
                timestamp=now(),
                path=request.path,
                country=country,
                city=city
            )

        return self.get_response(request)
