#!/usr/bin/env python3
"""Master KillSwitch scaffold (Step 8)."""

import os
import sys

if os.geteuid() != 0:
    sys.exit(1)  # must be root
