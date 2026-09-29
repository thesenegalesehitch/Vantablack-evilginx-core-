"""Automated AiTM Flow - headless browser + proxy integration."""

from .automation import (
    AttackStep,
    AutomatedAiTMFlow,
    FlowConfig,
    register_automation_routes,
)

__all__ = [
    "AttackStep",
    "AutomatedAiTMFlow",
    "FlowConfig",
    "register_automation_routes",
]
