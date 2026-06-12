"""
Model-artifact storage helpers (Phase 11.3 / 11.8).

Artifacts live under settings.INTELLIGENCE_MODELS/<attack>/ outside the Django
app so they survive code redeploys. Files: model_current.pkl, *_current.pkl,
versioned model_v{N}.pkl, and metadata.json. Directory is chmod 750, owned by
the cerberus user in production.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

logger = logging.getLogger("cerberus.intelligence")


def models_root() -> Path:
    from django.conf import settings
    return Path(settings.INTELLIGENCE_MODELS)


def model_dir(attack: str) -> Path:
    d = models_root() / attack
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o750)
    except OSError:
        pass  # best-effort on non-POSIX / dev
    return d


def training_data_dir() -> Path:
    from django.conf import settings
    d = Path(settings.INTELLIGENCE_TRAINING_DATA)
    d.mkdir(parents=True, exist_ok=True)
    return d


def datasets_dir() -> Path:
    from django.conf import settings
    return Path(settings.INTELLIGENCE_DATASETS)


def save_pickle(obj, path: Path):
    import joblib
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, path)
    try:
        os.chmod(path, 0o640)
    except OSError:
        pass


def load_pickle(path: Path):
    import joblib
    return joblib.load(path)


def read_metadata(attack: str) -> dict:
    p = model_dir(attack) / "metadata.json"
    if p.exists():
        try:
            return json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
    return {}


def write_metadata(attack: str, meta: dict):
    p = model_dir(attack) / "metadata.json"
    p.write_text(json.dumps(meta, indent=2, default=str))
    try:
        os.chmod(p, 0o640)
    except OSError:
        pass


def next_version(attack: str) -> int:
    return int(read_metadata(attack).get("version", 0)) + 1


def training_log(msg: str):
    """Append to /opt/cerberus/logs/training.log (Phase 11.3)."""
    from django.conf import settings
    from django.utils import timezone
    try:
        path = Path(settings.ML_TRAINING_LOG)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(f"{timezone.now().isoformat()}  {msg}\n")
    except OSError:
        pass
    logger.info("[train] %s", msg)
