from django.conf import settings


def web_push_settings(_request):
    return {
        "WEB_PUSH_PUBLIC_KEY": getattr(settings, "WEB_PUSH_PUBLIC_KEY", ""),
    }
