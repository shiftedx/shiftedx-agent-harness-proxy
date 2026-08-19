"""Bounded downstream admission and upstream-operation ownership."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from .config import Settings
from .errors import ProxyError
from .transport import Upstream

_GLOBAL_BUDGET_KEY = "global"


@dataclass
class _PrincipalBudget:
    semaphore: asyncio.Semaphore
    arrivals: deque[float] = field(default_factory=deque)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    last_used: float = field(default_factory=time.monotonic)
    references: int = 0


@dataclass(frozen=True)
class AdmissionSnapshot:
    active: int
    queued: int
    upstream_active: int
    admission_rejections: int
    rate_rejections: int


class AdmissionController:
    """Own request lifetime gates without retaining request content or identity."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._admission = asyncio.Semaphore(settings.admission_limit)
        self._upstream = asyncio.Semaphore(settings.concurrency_limit)
        self._principals: dict[str, _PrincipalBudget] = {}
        self._principals_lock = asyncio.Lock()
        self.active = 0
        self.queued = 0
        self.upstream_active = 0
        self.admission_rejections = 0
        self.rate_rejections = 0

    def snapshot(self) -> AdmissionSnapshot:
        return AdmissionSnapshot(
            active=self.active,
            queued=self.queued,
            upstream_active=self.upstream_active,
            admission_rejections=self.admission_rejections,
            rate_rejections=self.rate_rejections,
        )

    @asynccontextmanager
    async def admit(self, principal_key: str | None) -> AsyncIterator[None]:
        """Acquire global and optional principal budgets before reading a body."""
        self.queued += 1
        global_acquired = False
        principal: _PrincipalBudget | None = None
        principal_acquired = False
        active = False
        try:
            principal = await self._principal(principal_key)
            if principal is not None:
                try:
                    await self._acquire(principal.semaphore, "principal_concurrency_limited")
                    principal_acquired = True
                except BaseException:
                    await self._release_principal_reference(principal)
                    principal = None
                    raise
            await self._acquire(self._admission, "admission_overloaded")
            global_acquired = True
            if principal is not None:
                await self._charge_rate(principal)
            self.queued -= 1
            self.active += 1
            active = True
            yield
        finally:
            if not active:
                self.queued -= 1
            if principal_acquired and principal is not None:
                principal.semaphore.release()
                principal.last_used = time.monotonic()
                await self._release_principal_reference(principal)
            if global_acquired:
                if active:
                    self.active -= 1
                self._admission.release()
            await self._prune_principals()

    @asynccontextmanager
    async def upstream_slot(self) -> AsyncIterator[None]:
        """Acquire one upstream connection/work slot for exactly one operation."""
        try:
            await asyncio.wait_for(
                self._upstream.acquire(), timeout=self.settings.concurrency_wait_seconds
            )
        except TimeoutError as exc:
            raise ProxyError(
                503,
                "upstream_concurrency_limited",
                "Upstream capacity is unavailable.",
                headers={"Retry-After": str(self.settings.overload_retry_after_seconds)},
            ) from exc
        self.upstream_active += 1
        try:
            yield
        finally:
            self.upstream_active -= 1
            self._upstream.release()

    async def _acquire(self, semaphore: asyncio.Semaphore, code: str) -> None:
        try:
            await asyncio.wait_for(semaphore.acquire(), timeout=self.settings.admission_wait_seconds)
        except TimeoutError as exc:
            self.admission_rejections += 1
            raise ProxyError(
                429,
                code,
                "Request admission is temporarily unavailable.",
                headers={"Retry-After": str(self.settings.overload_retry_after_seconds)},
            ) from exc

    async def _principal(self, key: str | None) -> _PrincipalBudget | None:
        if key is None or self.settings.principal_budget_mode == "global":
            key = _GLOBAL_BUDGET_KEY
        async with self._principals_lock:
            budget = self._principals.get(key)
            if budget is None:
                budget = _PrincipalBudget(asyncio.Semaphore(self.settings.principal_concurrency_limit))
                self._principals[key] = budget
            budget.references += 1
            return budget

    async def _release_principal_reference(self, principal: _PrincipalBudget) -> None:
        async with self._principals_lock:
            principal.references -= 1

    async def _charge_rate(self, principal: _PrincipalBudget) -> None:
        now = time.monotonic()
        window = self.settings.principal_rate_window_seconds
        async with principal.lock:
            while principal.arrivals and principal.arrivals[0] <= now - window:
                principal.arrivals.popleft()
            if len(principal.arrivals) >= self.settings.principal_rate_limit:
                self.rate_rejections += 1
                raise ProxyError(
                    429,
                    "principal_rate_limited",
                    "Request admission is temporarily unavailable.",
                    headers={"Retry-After": str(self.settings.overload_retry_after_seconds)},
                )
            principal.arrivals.append(now)
            principal.last_used = now

    async def _prune_principals(self) -> None:
        if not self._principals:
            return
        now = time.monotonic()
        async with self._principals_lock:
            for key, principal in list(self._principals.items()):
                async with principal.lock:
                    expiry = now - self.settings.principal_rate_window_seconds
                    while principal.arrivals and principal.arrivals[0] <= expiry:
                        principal.arrivals.popleft()
                    if (
                        principal.references == 0
                        and not principal.arrivals
                        and principal.last_used <= now - self.settings.principal_rate_window_seconds
                    ):
                        self._principals.pop(key, None)


class BoundedUpstream:
    """Apply the upstream-operation budget to every delegated upstream call."""

    def __init__(self, upstream: Upstream, admission: AdmissionController) -> None:
        self._upstream = upstream
        self._admission = admission

    async def chat(self, payload: dict[str, Any], request_headers: dict[str, str]) -> dict[str, Any]:
        async with self._admission.upstream_slot():
            return await self._upstream.chat(payload, request_headers)

    async def models(self, request_headers: dict[str, str]) -> dict[str, Any]:
        async with self._admission.upstream_slot():
            return await self._upstream.models(request_headers)

    async def ready(self) -> bool:
        async with self._admission.upstream_slot():
            return await self._upstream.ready()

    async def close(self) -> None:
        await self._upstream.close()
