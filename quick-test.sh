#!/bin/bash
echo "=== Quick Automated Error Handling Tests ==="
echo ""

PASS=0
FAIL=0

# Test 1: Syntax Check
echo "Test 1: Script Syntax Validation"
if bash -n vps-wizard.sh 2>/dev/null; then
  echo "✓ PASS: Script syntax is valid"
  ((PASS++))
else
  echo "✗ FAIL: Script has syntax errors"
  ((FAIL++))
fi
echo ""

# Test 2: Required Functions Exist
echo "Test 2: Required Functions"
for func in "error_exit" "log_error" "install_dependency" "install_app" "run_custom_command"; do
  if grep -q "^$func()" vps-wizard.sh; then
    echo "✓ Function $func exists"
    ((PASS++))
  else
    echo "✗ Function $func missing"
    ((FAIL++))
  fi
done
echo ""

# Test 3: Error Handling Keywords
echo "Test 3: Error Handling Keywords"
keywords=(
  "error_exit:Exit handler"
  "log_error:Error logger"
  "ERROR_LOG:Error log file"
  "set -euo pipefail:Strict mode"
  "trap:Error trap"
)

for entry in "${keywords[@]}"; do
  IFS=':' read -r keyword desc <<< "$entry"
  if grep -q "$keyword" vps-wizard.sh; then
    echo "✓ $desc present"
    ((PASS++))
  else
    echo "✗ $desc missing"
    ((FAIL++))
  fi
done
echo ""

# Test 4: Validation Patterns
echo "Test 4: Input Validation"
validations=(
  "-z.*USERNAME:Username empty check"
  "=~.*\^:Regex validation"
  "-gt 32:Length check"
  "id.*USERNAME:User exists check"
  "-f.*ssh_config:File exists check"
)

for entry in "${validations[@]}"; do
  IFS=':' read -r pattern desc <<< "$entry"
  if grep -q "$pattern" vps-wizard.sh; then
    echo "✓ $desc found"
    ((PASS++))
  else
    echo "✗ $desc missing"
    ((FAIL++))
  fi
done
echo ""

# Test 5: Error Recovery
echo "Test 5: Error Recovery Mechanisms"
recovery=(
  "2>/dev/null:Error suppression"
  "failed.*=():Failure tracking"
  "rm -f.*temp:Temp file cleanup"
  "backup:Backup creation"
)

for entry in "${recovery[@]}"; do
  IFS=':' read -r pattern desc <<< "$entry"
  if grep -q "$pattern" vps-wizard.sh; then
    echo "✓ $desc found"
    ((PASS++))
  else
    echo "✗ $desc missing"
    ((FAIL++))
  fi
done
echo ""

# Summary
echo "======================================"
echo "Results: $PASS passed, $FAIL failed"
echo "======================================"

if [ $FAIL -eq 0 ]; then
  echo "✓ All automated tests passed!"
  echo ""
  echo "Next steps:"
  echo "  1. Review MANUAL_TEST_GUIDE.md for interactive tests"
  echo "  2. Run: sudo ./vps-wizard.sh"
  echo "  3. Monitor: sudo tail -f /var/log/vps-setup-errors.log"
  exit 0
else
  echo "✗ Some tests failed - review error handling code"
  exit 1
fi
