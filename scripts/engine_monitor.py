#!/usr/bin/env python3
"""
Phase 3.3 — Engine watchdog daemon.

Every 30s:
  * checks Suricata and Snort via `systemctl is-active`,
  * auto-restarts a crashed engine (within the 30s loop → Constraint #10),
  * updates the EngineStatus rows + pushes to the /ws/engine/ channel,
  * mirrors health to Redis for fast dashboard reads,
  * logs every event to /opt/cerberus/logs/engine.log.

Runs as the cerberus user via cerberus-engine-monitor.service. Engine restarts
go through the same narrow sudoers entry used by the API (systemd/sudoers.d-cerberus).
"""
import os
import sys
import time
import json
import logging
import subprocess
from datetime import datetime, timezone

# --- Django bootstrap -------------------------------------------------------
BACKEND = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backend")
sys.path.insert(0, os.path.abspath(BACKEND))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cerberus.settings")

import django  # noqa: E402
django.setup()

from django.conf import settings  # noqa: E402
from django.utils import timezone as dj_tz  # noqa: E402
from engine.models import EngineStatus  # noqa: E402
from engine.serializers import EngineStatusSerializer  # noqa: E402

ENGINES = ["suricata", "snort"]
POLL_SECONDS = 30
RESTART_BACKOFF = {}  # engine -> last restart epoch, to avoid restart storms

LOGFILE = settings.CERBERUS_LOGDIR / "engine.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOGFILE), logging.StreamHandler()],
)
log = logging.getLogger("cerberus.watchdog")


def systemctl(action: str, unit: str) -> tuple[int, str]:
    try:
        r = subprocess.run(["/usr/bin/sudo", "-n", "/usr/bin/systemctl", action, unit],
                           capture_output=True, text=True, timeout=30, check=False)
        return r.returncode, (r.stdout or r.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)


def is_active(engine: str) -> bool:
    rc, out = systemctl("is-active", f"cerberus-{engine}.service")
    return out == "active"


def get_pid(engine: str):
    try:
        out = subprocess.check_output(
            ["/usr/bin/systemctl", "show", "-p", "MainPID", "--value", f"cerberus-{engine}.service"],
            text=True,
        ).strip()
        pid = int(out)
        return pid or None
    except (subprocess.CalledProcessError, ValueError, FileNotFoundError):
        return None


def redis_client():
    try:
        import redis
        return redis.Redis.from_url(settings.REDIS_URL)
    except Exception as exc:  # noqa: BLE001
        log.warning("Redis unavailable: %s", exc)
        return None


def broadcast(statuses):
    try:
        from asgiref.sync import async_to_sync
        from channels.layers import get_channel_layer
        layer = get_channel_layer()
        if layer:
            async_to_sync(layer.group_send)(
                "engine", {"type": "engine.update", "data": statuses}
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("WS broadcast failed: %s", exc)


def alert_count(engine: str) -> int:
    from threats.models import Threat
    return Threat.objects.filter(engine=engine).count()


def check_once(r):
    statuses = []
    for engine in ENGINES:
        active = is_active(engine)
        pid = get_pid(engine) if active else None
        st, _ = EngineStatus.objects.get_or_create(engine_name=engine)

        if active:
            st.status = EngineStatus.State.RUNNING
            st.pid = pid
            st.last_heartbeat = dj_tz.now()
        else:
            st.status = EngineStatus.State.CRASHED
            log.error("%s is DOWN — attempting restart", engine)
            now = time.time()
            # Backoff: don't hammer restarts faster than every 20s.
            if now - RESTART_BACKOFF.get(engine, 0) > 20:
                RESTART_BACKOFF[engine] = now
                st.status = EngineStatus.State.RESTARTING
                rc, out = systemctl("restart", f"cerberus-{engine}.service")
                st.last_restart = dj_tz.now()
                st.restart_count += 1
                if rc == 0:
                    log.info("Restarted %s successfully", engine)
                else:
                    log.error("Restart of %s failed: %s", engine, out)

        st.alerts_count = alert_count(engine)
        st.save()
        data = EngineStatusSerializer(st).data
        statuses.append(data)
        if r:
            try:
                r.set(f"cerberus:engine:{engine}", json.dumps(data, default=str))
            except Exception:  # noqa: BLE001
                pass

    broadcast(statuses)
    return statuses


def main():
    log.info("Engine watchdog starting (poll every %ss)", POLL_SECONDS)
    r = redis_client()
    while True:
        try:
            check_once(r)
        except Exception as exc:  # noqa: BLE001
            log.exception("watchdog iteration failed: %s", exc)
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
