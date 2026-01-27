"""
Django 설정 파일 (config 프로젝트)

Django 6.0의 'django-admin startproject' 명령으로 생성됨.

이 파일에 대한 자세한 정보:
https://docs.djangoproject.com/en/6.0/topics/settings/

전체 설정 목록 및 값:
https://docs.djangoproject.com/en/6.0/ref/settings/
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# 환경 변수 로드
load_dotenv()

# 프로젝트 기본 경로 설정: BASE_DIR / 'subdir' 형태로 사용
BASE_DIR = Path(__file__).resolve().parent.parent


# 개발 환경 빠른 설정 - 프로덕션에는 부적합
# 배포 체크리스트: https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)) == "True"


def _env_list(name: str, default: str = "") -> list[str]:
    return [value.strip() for value in os.getenv(name, default).split(",") if value.strip()]


# 보안 경고: 프로덕션 환경에서는 시크릿 키를 반드시 비밀로 유지할 것!
SECRET_KEY = os.getenv("SECRET_KEY", "django-insecure-dev-key")

# 보안 경고: 프로덕션 환경에서는 DEBUG를 켜지 말 것!
DEBUG = _env_bool("DEBUG", True)

ALLOWED_HOSTS = _env_list("ALLOWED_HOSTS", "localhost,127.0.0.1" if DEBUG else "")


# 애플리케이션 정의

INSTALLED_APPS = [
    "daphne",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "drf_spectacular",
    "channels",
    "corsheaders",
    "apps.accounts",
    "apps.chess",
    "apps.notifications",
    "apps.core",  # S3 이미지 업로드
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "corsheaders.middleware.CorsMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"


# 데이터베이스
# https://docs.djangoproject.com/en/6.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "chessdb"),
        "USER": os.getenv("DB_USER", "postgres"),
        "PASSWORD": os.getenv("DB_PASSWORD", "postgres"),
        "HOST": os.getenv("DB_HOST", "localhost"),  # 하이브리드: localhost, Docker: "db"
        "PORT": os.getenv("DB_PORT", "5432"),
    }
}


# 비밀번호 검증
# https://docs.djangoproject.com/en/6.0/ref/settings/#auth-password-validators
# 커스텀 검증을 Serializer에서 처리하므로 Django 기본 validators는 비활성화

AUTH_PASSWORD_VALIDATORS = []


# 국제화 (i18n)
# https://docs.djangoproject.com/en/6.0/topics/i18n/

LANGUAGE_CODE = "ko-kr"

TIME_ZONE = "Asia/Seoul"

USE_I18N = True

USE_TZ = True


# 정적 파일 (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/6.0/howto/static-files/

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

# 미디어 파일
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# 기본 Primary Key 필드 타입
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# ASGI 애플리케이션
ASGI_APPLICATION = "config.asgi.application"

# Channels 설정 (Redis)
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [(os.getenv("REDIS_HOST", "localhost"), int(os.getenv("REDIS_PORT", "6379")))],
        },
    },
}

# Redis 캐시 설정
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/1",
    }
}

# CORS 설정 (템플릿 중심이면 기본 비활성)
CORS_ALLOW_ALL_ORIGINS = _env_bool("CORS_ALLOW_ALL_ORIGINS", False)
CORS_ALLOWED_ORIGINS = _env_list("CORS_ALLOWED_ORIGINS")

CSRF_TRUSTED_ORIGINS = _env_list("CSRF_TRUSTED_ORIGINS")

# WhiteNoise 설정
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}

# 보안 설정 (프로덕션 기준, DEBUG=False일 때 기본 활성화)
SECURE_PROXY_SSL_HEADER = (
    "HTTP_X_FORWARDED_PROTO",
    "https",
)
SECURE_SSL_REDIRECT = _env_bool("SECURE_SSL_REDIRECT", not DEBUG)
SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", not DEBUG)
CSRF_COOKIE_SECURE = _env_bool("CSRF_COOKIE_SECURE", not DEBUG)
SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "0" if DEBUG else "3600"))
SECURE_HSTS_INCLUDE_SUBDOMAINS = _env_bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", not DEBUG)
SECURE_HSTS_PRELOAD = _env_bool("SECURE_HSTS_PRELOAD", not DEBUG)
SECURE_REFERRER_POLICY = os.getenv("SECURE_REFERRER_POLICY", "same-origin")

# 인증 설정
AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"

# Django REST Framework 설정
REST_FRAMEWORK = {
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticatedOrReadOnly",
    ],
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
    ],
    "DEFAULT_PARSER_CLASSES": [
        "rest_framework.parsers.JSONParser",
    ],
    "EXCEPTION_HANDLER": "apps.core.exceptions.custom_exception_handler",
}

# Swagger/OpenAPI 설정
SPECTACULAR_SETTINGS = {
    "TITLE": "Chess Multiplayer API",
    "DESCRIPTION": "Django 6.0 기반 실시간 체스 멀티플레이 게임 API",
    "VERSION": "0.1.1",
    "SERVE_INCLUDE_SCHEMA": False,
    "SCHEMA_PATH_PREFIX": r"/api",
}

# Logging 설정
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "[{levelname}] {asctime} {name} {message}",
            "style": "{",
        },
        "simple": {
            "format": "[{levelname}] {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
    "loggers": {
        "django": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
        "apps.accounts": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": False,
        },
    },
}

# 이메일 설정
EMAIL_BACKEND = os.getenv("EMAIL_BACKEND", "django.core.mail.backends.console.EmailBackend")
EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.naver.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER", "")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD", "")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL", "qkralstn8070@naver.com")

# 도메인/프론트엔드 URL (이메일 링크용)
DOMAIN = os.getenv("DOMAIN", "")
FRONTEND_URL = os.getenv("FRONTEND_URL", DOMAIN or "http://localhost:8000")

# 소셜 로그인 설정
# Google OAuth
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", f"{FRONTEND_URL}/auth/google/callback")

# Kakao OAuth
KAKAO_CLIENT_ID = os.getenv("KAKAO_CLIENT_ID", "")
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET", "")
KAKAO_REDIRECT_URI = os.getenv("KAKAO_REDIRECT_URI", f"{FRONTEND_URL}/auth/kakao/callback")

# Naver OAuth
NAVER_CLIENT_ID = os.getenv("NAVER_CLIENT_ID", "")
NAVER_CLIENT_SECRET = os.getenv("NAVER_CLIENT_SECRET", "")
NAVER_REDIRECT_URI = os.getenv("NAVER_REDIRECT_URI", f"{FRONTEND_URL}/auth/naver/callback")

# AWS S3 설정 (이미지 업로드용)
AWS_S3_ACCESS_KEY_ID = os.getenv("AWS_S3_ACCESS_KEY_ID", "")
AWS_S3_SECRET_ACCESS_KEY = os.getenv("AWS_S3_SECRET_ACCESS_KEY", "")
AWS_S3_BUCKET_NAME = os.getenv("AWS_S3_BUCKET_NAME", "")
AWS_S3_REGION = os.getenv("AWS_S3_REGION", "ap-northeast-2")

# Celery 설정
CELERY_BROKER_URL = os.getenv(
    "CELERY_BROKER_URL",
    f"redis://{os.getenv('REDIS_HOST', 'localhost')}:{os.getenv('REDIS_PORT', '6379')}/0",
)
CELERY_RESULT_BACKEND = CELERY_BROKER_URL
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = TIME_ZONE
# Beat 스케줄은 config/celery.py에서 관리
