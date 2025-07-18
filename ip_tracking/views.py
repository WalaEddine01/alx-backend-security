from django.shortcuts import render
from django.http import JsonResponse
from ratelimit.decorators import ratelimit


@ratelimit(key='ip', rate='10/m', method='POST', block=True)
@ratelimit(key='ip', rate='5/m', method='POST', block=True)
def login_view(request):
    if request.method == 'POST':
        if getattr(request, 'limits', False):
            return JsonResponse({"error": "Rate limit exceeded"}, status=429)
        return JsonResponse({"message": "Login attempt recorded"})
    return JsonResponse({"detail": "Only POST supported"}, status=405)
