#!/bin/bash

set -e

echo "PostgreSQL is ready (healthcheck passed)"

echo "Running migrations..."
uv run python manage.py migrate --noinput

echo "Creating superuser if not exists..."
uv run python manage.py shell -c "
from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()
try:
    if not User.objects.filter(email='admin@example.com').exists():
        User.objects.create_superuser(
            email='admin@example.com',
            nickname='admin',
            password='admin'
        )
        print('✅ Superuser created successfully')
    else:
        print('ℹ️  Superuser already exists')
except IntegrityError:
    print('ℹ️  Superuser already exists (race condition)')
except Exception as e:
    print(f'⚠️  Error creating superuser: {e}')
"

echo "Starting server..."
cd /app
exec .venv/bin/python -m daphne -b 0.0.0.0 -p 8000 config.asgi:application
