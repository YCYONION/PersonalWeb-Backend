# analytics/middleware.py
from .models import PageView

class PageViewMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        # Log GET requests; you can customize which paths to log.
        if request.method == 'GET' and not request.path.startswith('/admin'):
            ip = request.META.get('REMOTE_ADDR')
            session_key = request.session.session_key
            # You might want to log only specific pages (e.g., public home and photo pages)
            # For example, log if the path is "/" or starts with "/photos/"
            if request.path == '/' or request.path.startswith('/photos/'):
                PageView.objects.create(
                    page=request.path,
                    ip_address=ip,
                    session_key=session_key
                )
        return response
