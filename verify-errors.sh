#!/bin/bash
echo "=== VPS Wizard Error Handling Verification ==="
SCRIPT="vps-wizard.sh"
PASS=0
FAIL=0

check() {
  if grep -q "$1" "$SCRIPT"; then
    echo "✓ $2"
    ((PASS++))
  else
    echo "✗ $2"
    ((FAIL++))
  fi
}

check "set -euo pipefail" "Strict mode enabled"
check "error_exit()" "Error exit function"
check "ERROR_LOG=" "Error log file"
check "trap.*ERR" "Error trap"
check "log_error()" "Error logging"
check "install_dependency()" "Dependency validation"
check "temp_log" "Command output capture"
check "failed_packages" "Package tracking"
check "failed_commands" "Command tracking"
check "USERNAME.*=~" "Username validation"
check "ssh_config.*backup" "SSH backup"
check "sshd -t" "SSH validation"
check "who.*grep" "User active check"
check "GH_USER.*=~" "GitHub username validation"
check "TEMP_KEYS" "Temp file handling"
check "URL.*=~" "URL validation"

echo ""
echo "Results: $PASS passed, $FAIL failed"
[ $FAIL -eq 0 ] && echo "✓ All checks passed!" || echo "✗ Some checks failed"
