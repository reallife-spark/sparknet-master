#!/usr/bin/env python3
"""Minimal registry push listener stub (Step 7)."""

import os

DEFAULT_BIND = os.environ.get("SPARKNET_REGISTRY_BIND", "10.100.0.1:8090")
assert DEFAULT_BIND.startswith("10.100.0.1:"), "must bind 10.100.0.1 only"
