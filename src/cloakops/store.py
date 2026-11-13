"""Local state: sessions (key + mapping table + learned terms), seed dictionary, config.

Phase 1 stores sessions as plain JSON files, readable by the owner only (directory 0700, files
0600, refused if more open), with a TTL: an expired session is deleted when touched. Encryption
at rest is phase 3 (ADR 0016). The files hold real values: they never leave the machine and are
never written inside a repository by default.

Layout under $CLOAKOPS_HOME (default ~/.local/state/cloakops):

    sessions/<name>.json   one per session
    seed.txt               the seed dictionary (ADR 0007)
    config.toml            optional: organization_domains, internal_suffixes
"""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cloakops.errors import FailClosedError
from cloakops.propagate import Propagator
from cloakops.pseudo.session import Session

STATE_VERSION = 1
DEFAULT_TTL = timedelta(hours=24)
_SESSION_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


class StoreError(FailClosedError):
    """Local state that cannot be trusted (permissions, corruption) or an invalid name."""


def default_home() -> Path:
    env = os.environ.get("CLOAKOPS_HOME")
    if env:
        return Path(env)
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "cloakops"


def _private(path: Path, what: str) -> None:
    if os.name == "posix" and path.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise StoreError(f"{what} {path} is accessible by group or others: chmod 700/600 it")


@dataclass
class Config:
    organization_domains: tuple[str, ...] = ()
    internal_suffixes: tuple[str, ...] | None = None  # None: the built-in defaults
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class LoadedSession:
    name: str
    session: Session
    propagator: Propagator
    created_at: datetime


class Store:
    def __init__(self, home: Path | None = None, ttl: timedelta = DEFAULT_TTL) -> None:
        self.home = home if home is not None else default_home()
        self.ttl = ttl

    # --- directories -------------------------------------------------------------------------

    def _ensure_dir(self, path: Path) -> Path:
        if path.exists():
            _private(path, "directory")
        else:
            path.mkdir(mode=0o700, parents=True)
            path.chmod(0o700)  # mkdir's mode is filtered by the umask
        return path

    @property
    def sessions_dir(self) -> Path:
        self._ensure_dir(self.home)
        return self._ensure_dir(self.home / "sessions")

    @property
    def seed_path(self) -> Path:
        return self.home / "seed.txt"

    def _session_path(self, name: str) -> Path:
        if not _SESSION_NAME.fullmatch(name):
            raise StoreError("session names use letters, digits, '.', '_' and '-' (max 64)")
        return self.sessions_dir / f"{name}.json"

    # --- config ------------------------------------------------------------------------------

    def config(self) -> Config:
        path = self.home / "config.toml"
        if not path.exists():
            return Config()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        suffixes = data.get("internal_suffixes")
        return Config(
            organization_domains=tuple(data.get("organization_domains", ())),
            internal_suffixes=tuple(suffixes) if suffixes is not None else None,
            extra={
                k: v
                for k, v in data.items()
                if k not in ("organization_domains", "internal_suffixes")
            },
        )

    # --- sessions ----------------------------------------------------------------------------

    def _expired(self, created_at: datetime) -> bool:
        return datetime.now(UTC) - created_at > self.ttl

    def exists(self, name: str) -> bool:
        return self._session_path(name).exists()

    def load(self, name: str) -> LoadedSession:
        """The session `name`, or a fresh one if it does not exist or has expired."""
        path = self._session_path(name)
        if not path.exists():
            return LoadedSession(name, Session(), Propagator(), datetime.now(UTC))
        _private(path, "session file")
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            created_at = datetime.fromisoformat(state["created_at"])
            if state.get("version") != STATE_VERSION:
                raise ValueError("unsupported session version")
            if self._expired(created_at):
                path.unlink()
                return LoadedSession(name, Session(), Propagator(), datetime.now(UTC))
            session = Session.from_state(state["session"])
            propagator = Propagator()
            propagator.import_state(state["propagation"])
        except (KeyError, ValueError, TypeError) as exc:
            raise StoreError(f"session {name!r} is corrupted") from exc
        return LoadedSession(name, session, propagator, created_at)

    def save(self, loaded: LoadedSession) -> None:
        path = self._session_path(loaded.name)
        state = {
            "version": STATE_VERSION,
            "created_at": loaded.created_at.isoformat(),
            "session": loaded.session.export_state(),
            "propagation": loaded.propagator.export_state(),
        }
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle)
        os.replace(tmp, path)  # atomic: a crash never leaves a half-written session

    def delete(self, name: str) -> bool:
        path = self._session_path(name)
        if path.exists():
            path.unlink()
            return True
        return False

    def sessions(self) -> Iterator[tuple[str, datetime, bool]]:
        """(name, created_at, expired) for every stored session."""
        for path in sorted(self.sessions_dir.glob("*.json")):
            try:
                created_at = datetime.fromisoformat(json.loads(path.read_text())["created_at"])
            except (KeyError, ValueError):
                continue
            yield path.stem, created_at, self._expired(created_at)

    def purge_expired(self) -> int:
        removed = 0
        for name, _, expired in list(self.sessions()):
            if expired:
                removed += self.delete(name)
        return removed

    # --- seed dictionary ---------------------------------------------------------------------

    def write_seed(self, lines: list[str]) -> None:
        self._ensure_dir(self.home)
        fd = os.open(self.seed_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("".join(f"{line}\n" for line in lines))
        self.seed_path.chmod(0o600)

    def read_seed_lines(self) -> list[str]:
        if not self.seed_path.exists():
            return []
        _private(self.seed_path, "seed dictionary")
        return self.seed_path.read_text(encoding="utf-8").splitlines()
