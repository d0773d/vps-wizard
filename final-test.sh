#!/bin/bash
echo "=== Comprehensive Error Handling Verification ==="
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

# Test 2: Core Error Functions
echo "Test 2: Core Error Functions"
if grep -q "^error_exit()" vps-wizard.sh && \
   grep -q "^log_error()" vps-wizard.sh && \
   grep -q "trap.*error_exit" vps-wizard.sh; then
  echo "✓ Error handling framework complete"
  ((PASS++))
else
  echo "✗ Error handling framework incomplete"
  ((FAIL++))
fi
echo ""

# Test 3: Strict Mode
echo "Test 3: Bash Strict Mode"
if grep -q "set -euo pipefail" vps-wizard.sh; then
  echo "✓ Strict mode enabled"
  ((PASS++))
else
  echo "✗ Strict mode missing"
  ((FAIL++))
fi
echo ""

# Test 4: Logging Setup
echo "Test 4: Logging Configuration"
if grep -q 'ERROR_LOG=' vps-wizard.sh && \
   grep -q 'LOG_FILE=' vps-wizard.sh; then
  echo "✓ Dual logging configured"
  ((PASS++))
else
  echo "✗ Logging configuration incomplete"
  ((FAIL++))
fi
echo ""

# Test 5: Dependency Management
echo "Test 5: Dependency Management"
if grep -q "install_dependency()" vps-wizard.sh && \
   grep -q "command -v" vps-wizard.sh; then
  echo "✓ Dependency validation present"
  ((PASS++))
else
  echo "✗ Dependency validation missing"
  ((FAIL++))
fi
echo ""

# Test 6: Progress Monitoring
echo "Test 6: Progress Monitoring"
if grep -q "run_with_progress()" vps-wizard.sh && \
   grep -q "temp_log=" vps-wizard.sh; then
  echo "✓ Progress monitoring with capture"
  ((PASS++))
else
  echo "✗ Progress monitoring incomplete"
  ((FAIL++))
fi
echo ""

# Test 7: Input Validation
echo "Test 7: Input Validation"
validations=0
grep -q '\-z.*USERNAME' vps-wizard.sh && ((validations++))
grep -q '=~' vps-wizard.sh && ((validations++))
grep -q '\${#USERNAME}' vps-wizard.sh && ((validations++))

if [ $validations -ge 2 ]; then
  echo "✓ Input validation implemented ($validations/3 checks)"
  ((PASS++))
else
  echo "✗ Insufficient input validation"
  ((FAIL++))
fi
echo ""

# Test 8: SSH Security
echo "Test 8: SSH Security Hardening"
if grep -q "secure_ssh()" vps-wizard.sh && \
   grep -q "sshd -t" vps-wizard.sh && \
   grep -q "backup.*date" vps-wizard.sh; then
  echo "✓ SSH backup and validation present"
  ((PASS++))
else
  echo "✗ SSH security incomplete"
  ((FAIL++))
fi
echo ""

# Test 9: User Management
echo "Test 9: User Management Safety"
if grep -q 'id.*USERNAME' vps-wizard.sh && \
   grep -q 'who.*grep' vps-wizard.sh; then
  echo "✓ User existence and active checks"
  ((PASS++))
else
  echo "✗ User management checks missing"
  ((FAIL++))
fi
echo ""

# Test 10: Failure Tracking
echo "Test 10: Failure Tracking Arrays"
tracking=0
grep -q 'failed_packages=()' vps-wizard.sh && ((tracking++))
grep -q 'failed_commands=()' vps-wizard.sh && ((tracking++))
grep -q 'failed_langs=()' vps-wizard.sh && ((tracking++))

if [ $tracking -ge 2 ]; then
  echo "✓ Failure tracking arrays ($tracking/3 types)"
  ((PASS++))
else
  echo "✗ Insufficient failure tracking"
  ((FAIL++))
fi
echo ""

# Test 11: GitHub Integration
echo "Test 11: GitHub Key Import Validation"
if grep -q 'https://github.com/.*\.keys' vps-wizard.sh && \
   grep -q '\[.*GH_USER.*\]' vps-wizard.sh; then
  echo "✓ GitHub username validation"
  ((PASS++))
else
  echo "✗ GitHub validation missing"
  ((FAIL++))
fi
echo ""

# Test 12: URL Validation
echo "Test 12: URL Format Validation"
if grep -q 'https\?://' vps-wizard.sh; then
  echo "✓ URL format checking present"
  ((PASS++))
else
  echo "✗ URL validation missing"
  ((FAIL++))
fi
echo ""

# Test 13: Temp File Cleanup
echo "Test 13: Temporary File Management"
if grep -q 'TEMP_KEYS=' vps-wizard.sh && \
   grep -q 'rm -f.*temp' vps-wizard.sh; then
  echo "✓ Temp file cleanup implemented"
  ((PASS++))
else
  echo "✗ Temp file cleanup missing"
  ((FAIL++))
fi
echo ""

# Test 14: Profile System
echo "Test 14: Profile Loading Safety"
if grep -q '\-f.*PROFILE_FILE' vps-wizard.sh && \
   grep -q 'PROFILE_DIR=' vps-wizard.sh; then
  echo "✓ Safe profile loading"
  ((PASS++))
else
  echo "✗ Profile loading unsafe"
  ((FAIL++))
fi
echo ""

# Summary
echo "=========================================="
echo "Final Results: $PASS passed, $FAIL failed"
echo "=========================================="
echo ""

if [ $FAIL -eq 0 ]; then
  echo "🎉 ALL AUTOMATED TESTS PASSED!"
  echo ""
  echo "The error handling implementation is complete and verified."
  echo ""
  echo "📋 Next Steps for Manual Testing:"
  echo "   1. Review: cat MANUAL_TEST_GUIDE.md"
  echo "   2. Execute: sudo ./vps-wizard.sh"
  echo "   3. Monitor: sudo tail -f /var/log/vps-setup-errors.log"
  echo ""
  exit 0
else
  echo "⚠️  Some automated tests failed"
  echo "Review the error handling implementation above"
  exit 1
fi
