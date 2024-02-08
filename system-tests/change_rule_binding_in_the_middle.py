# system tests for rule binding.
#
# These tests are run as part of the system-tests/run.py script.
#
# The tests are run in the following order:
# 1. rule_binding_apply_test
# 2. rule_binding_delete_test
# 3. rule_binding_update_test

import subprocess
import sys
import time
import kill_in_the_middle

alert_manager_url = "http://localhost:9093"

