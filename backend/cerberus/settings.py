"""
Django settings for Cerberus Pi.

Security posture (Phases 2.4 & 10):
  * Secrets come exclusively from /opt/cerberus/secrets/.env (chmod 600).
  * PostgreSQL via Unix socket only — never a TCP host (Constraint #6).
  * Redis bound to localhost.
  * HTTPS-only cookies, CSRF, 30-min session timeout, strict host allow-list.
"""
from pathlib import Path
import os

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
CERBERUS_ROOT = Path(os.environ.get("CERBERUS_ROOT", "/opt/cerberus"))

# Load secrets from the install-generated env file (falls back to repo .env for dev).
for candidate in (CERBERUS_ROOT / "secrets" / ".env", BASE_DIR.parent / ".env"):
    if candidate.exists():
        load_dotenv(candidate)
        break


def env(key, default=None):
    return os.environ.get(key, default)


DEBUG = env("DJANGO_DEBUG", "0") == "1"

# In production the key MUST come from the install-generated .env. Refuse to boot
# with a placeholder/insecure key so the appliance can never run with a known key.
_INSECURE_KEYS = {"", "AUTO", "dev-insecure-change-me"}
SECRET_KEY = env("DJANGO_SECRET_KEY", "dev-insecure-change-me")
if not DEBUG and SECRET_KEY in _INSECURE_KEYS:
    from django.core.exceptions import ImproperlyConfigured

    raise ImproperlyConfigured(
        "DJANGO_SECRET_KEY is missing or still the placeholder. Run "
        "cerberus_install.sh to generate secrets, or set it in "
        "/opt/cerberus/secrets/.env before starting in production."
    )

ALLOWED_HOSTS = [h.strip() for h in env("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",") if h.strip()]
MGMT_HOST = env("CERBERUS_MGMT_HOST", "127.0.0.1")
if MGMT_HOST and MGMT_HOST not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(MGMT_HOST)

INSTALLED_APPS = [
    "daphne",  # must precede staticfiles for the ASGI runserver
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # third-party
    "rest_framework",
    "corsheaders",
    "django_filters",
    "channels",
    "django_celery_beat",
    # local apps
    "threats",
    "scanner",
    "logs",
    "reports",
    "engine",
    "auth_audit",  # Phase 10: login auditing + rate-limited admin auth
    "intelligence",  # Phase 11: AI anomaly detection (additive module)
]

MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "auth_audit.middleware.LoginAuditMiddleware",  # Phase 10 login audit
]

ROOT_URLCONF = "cerberus.urls"
WSGI_APPLICATION = "cerberus.wsgi.application"
ASGI_APPLICATION = "cerberus.asgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# --- Database: PostgreSQL via Unix socket only (Constraint #6) ---------------
# CERBERUS_DB_SQLITE=1 switches to a local SQLite file — for off-Pi development
# and CI only (no PostgreSQL on a Windows dev box). Never set in production.
if env("CERBERUS_DB_SQLITE", "0") == "1":
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": env("CERBERUS_SQLITE_PATH", str(BASE_DIR / "dev.sqlite3")),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": env("POSTGRES_DB", "cerberus"),
            "USER": env("POSTGRES_USER", "cerberus"),
            "PASSWORD": env("POSTGRES_PASSWORD", ""),
            # HOST as a path => libpq connects over the Unix socket, not TCP.
            "HOST": env("POSTGRES_HOST", "/var/run/postgresql"),
            "PORT": env("POSTGRES_PORT", ""),
        }
    }

# --- Channels (WebSockets) over Redis localhost ------------------------------
REDIS_URL = env("REDIS_URL", "redis://127.0.0.1:6379/0")
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {"hosts": [REDIS_URL]},
    }
}

# --- Celery ------------------------------------------------------------------
CELERY_BROKER_URL = env("CELERY_BROKER_URL", "redis://127.0.0.1:6379/1")
CELERY_RESULT_BACKEND = env("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/2")
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"
CELERY_TASK_TRACK_STARTED = True

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
     "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATIC_ROOT = CERBERUS_ROOT / "backend" / "staticfiles"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- DRF ---------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    # Every endpoint requires auth (Phase 10 / Constraint).
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_FILTER_BACKENDS": [
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.OrderingFilter",
    ],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.PageNumberPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.ScopedRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        # Login rate limit: 5 attempts / 10 min (Phase 10).
        "login": "5/10m",
    },
}

# Production: JSON only — drop the browsable API to shrink the attack surface.
if not DEBUG:
    REST_FRAMEWORK["DEFAULT_RENDERER_CLASSES"] = [
        "rest_framework.renderers.JSONRenderer",
    ]

# --- Security: HTTPS-only, session timeout (Phase 10) ------------------------
SESSION_COOKIE_AGE = 30 * 60          # 30-minute inactivity timeout
SESSION_SAVE_EVERY_REQUEST = True     # sliding expiry
SESSION_EXPIRE_AT_BROWSER_CLOSE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = False          # JS must read CSRF token for the SPA
X_FRAME_OPTIONS = "DENY"

if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_SSL_REDIRECT = False        # Nginx handles HTTP→HTTPS (Phase 9)
    SECURE_HSTS_SECONDS = 31536000
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
    SECURE_CONTENT_TYPE_NOSNIFF = True

# CSRF/CORS: only the management origin is trusted.
_mgmt_origin = f"https://{MGMT_HOST}"
CSRF_TRUSTED_ORIGINS = [_mgmt_origin, "https://localhost"]
CORS_ALLOWED_ORIGINS = [_mgmt_origin, "https://localhost"]
CORS_ALLOW_CREDENTIALS = True

# --- Cerberus app paths ------------------------------------------------------
CERBERUS_LOGDIR = CERBERUS_ROOT / "logs"
CERBERUS_REPORTS = CERBERUS_ROOT / "reports"
SURICATA_EVE = CERBERUS_LOGDIR / "suricata" / "eve.json"
SNORT_LOGDIR = CERBERUS_LOGDIR / "snort"
IPFS_API = env("IPFS_API", "/ip4/127.0.0.1/tcp/5001")
NVD_API_KEY = env("NVD_API_KEY", "")

# --- Phase 11: AI anomaly detection ------------------------------------------
# Model artifacts + training data live outside the Django app so they survive
# code redeploys. Default under CERBERUS_ROOT; override with INTELLIGENCE_ROOT
# (used in CI/dev where /opt/cerberus is not writable).
from pathlib import Path as _Path  # noqa: E402

INTELLIGENCE_ROOT = _Path(env("INTELLIGENCE_ROOT", str(CERBERUS_ROOT / "intelligence")))
INTELLIGENCE_MODELS = INTELLIGENCE_ROOT / "models"
INTELLIGENCE_TRAINING_DATA = INTELLIGENCE_ROOT / "training_data"
# Bundled seed datasets ship inside the app package.
INTELLIGENCE_DATASETS = BASE_DIR / "intelligence" / "datasets"
ML_BASELINE_HOURS = int(env("ML_BASELINE_HOURS", "72"))
ML_TRAINING_LOG = CERBERUS_LOGDIR / "training.log"
LLM_PROVIDER = env("LLM_PROVIDER", "")
OPENAI_API_KEY = env("OPENAI_API_KEY", "")
OLLAMA_HOST = env("OLLAMA_HOST", "http://127.0.0.1:11434")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {"verbose": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"}},
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "verbose"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}
