"""Mailbox Pivot package - mailbox rule injection."""

from .pivot import (
    RuleAction,
    InboxRule,
    MailboxPivot,
    register_pivot_routes,
)

__all__ = [
    "InboxRule",
    "MailboxPivot",
    "register_pivot_routes",
]
