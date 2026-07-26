from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


class FakeClock:
    """Deterministic clock for replay/tests. Advances on each tick() or now()+step."""

    def __init__(self, start: datetime | None = None, *, step_ms: int = 1) -> None:
        self._now = start or datetime(2020, 1, 1, tzinfo=timezone.utc)
        self._step = timedelta(milliseconds=step_ms)

    def now(self) -> datetime:
        return self._now

    def tick(self, steps: int = 1) -> datetime:
        self._now = self._now + (self._step * steps)
        return self._now

    def advance(self, **kwargs: float) -> datetime:
        self._now = self._now + timedelta(**kwargs)
        return self._now


_ACTIVE: Clock = SystemClock()


def get_clock() -> Clock:
    return _ACTIVE


def set_clock(clock: Clock | None) -> Clock:
    global _ACTIVE
    _ACTIVE = clock or SystemClock()
    return _ACTIVE


def utc_now() -> str:
    return get_clock().now().isoformat(timespec="microseconds").replace("+00:00", "Z")
