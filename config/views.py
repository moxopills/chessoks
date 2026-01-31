from django.shortcuts import render


def page_not_found(request, exception, template_name="errors/404.html"):
    return render(request, template_name, status=404)


def server_error(request, template_name="errors/500.html"):
    return render(request, template_name, status=500)
