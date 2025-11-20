"""SecureSpot: safe, authorized-only website vulnerability scanner package.

This tool is intended for defensive security testing on systems where you have
explicit, written permission from the owner. It performs only non-destructive
crawling, passive checks, and safe active checks that avoid exploitation.
"""

__all__ = [
    "config",
    "logging_utils",
    "auth",
    "crawler",
    "passive_checks",
    "active_checks",
    "reporting",
    "scanner",
]
