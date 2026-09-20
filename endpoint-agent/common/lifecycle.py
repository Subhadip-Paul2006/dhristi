# Drishti v0.1 — Endpoint Agent Lifecycle State Machine | Phase 01
from __future__ import annotations

import logging
from enum import Enum
from typing import Callable

logger = logging.getLogger("drishti.agent")


class AgentState(str, Enum):
    STARTING = "STARTING"
    WAITING_FOR_PAIRING = "WAITING_FOR_PAIRING"
    PAIRING = "PAIRING"
    CONNECTED = "CONNECTED"
    RECONNECTING = "RECONNECTING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    ERROR = "ERROR"


class LifecycleManager:
    """Manages and logs agent lifecycle transitions cleanly."""

    def __init__(self, initial_state: AgentState = AgentState.STARTING):
        self._state = initial_state
        self._listeners: list[Callable[[AgentState, AgentState], None]] = []

    @property
    def current_state(self) -> AgentState:
        return self._state

    @property
    def state(self) -> AgentState:
        return self._state

    def add_listener(self, listener: Callable[[AgentState, AgentState], None]) -> None:
        self._listeners.append(listener)

    def transition_to(self, new_state: AgentState, reason: str | None = None) -> None:
        if self._state == new_state:
            return
        old_state = self._state
        self._state = new_state
        log_msg = f"[Drishti Agent] Lifecycle: {old_state.value} -> {new_state.value}"
        if reason:
            log_msg += f" ({reason})"
        logger.info(log_msg)
        for listener in self._listeners:
            try:
                listener(old_state, new_state)
            except Exception as e:
                logger.debug("Error notifying lifecycle listener: %s", e)
