# Fixture: vulnerable Python command injection via os.system.
# Expected verify verdict: PROVEN (validates Fix 5 — Python runner enum).

import os
import sys


def run_command(user_input):
    # Vulnerable: user input concatenated into a shell command.
    cmd = "echo " + user_input
    return os.system(cmd)
