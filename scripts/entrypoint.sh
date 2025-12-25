#!/bin/bash

set -e

echo "PostgreSQL is ready (healthcheck passed)"

echo "Running migrations..."
uv run python manage.py migrate --noinput

echo "Creating superuser if not exists..."
uv run python manage.py shell -c "
from django.contrib.auth import get_user_model;
User = get_user_model();
if not User.objects.filter(username='admin').exists():
    User.objects.create_superuser('admin', 'admin@example.com', 'admin')
" || true

echo "Starting server..."
cd /app
exec .venv/bin/python -m daphne -b 0.0.0.0 -p 8000 config.asgi:application
