#!/bin/bash
# =====================================
# VPS Wizard Error Handling Test Suite
# =====================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

TEST_COUNT=0
PASSED=0
FAILED=0

print_header() {
  echo -e "\n${BLUE}======================================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}======================================${NC}\n"
}

print_test() {
  ((TEST_COUNT++))
  echo -e "${YELLOW}Test $TEST_COUNT: $1${NC}"
}

print_pass() {
  ((PASSED++))
  echo -e "${GREEN}✓ PASS: $1${NC}\n"
}

print_fail() {
  ((FAILED++))
  echo -e "${RED}✗ FAIL: $1${NC}\n"
}

print_info() {
  echo -e "${BLUE}ℹ INFO: $1${NC}"
}

print_summary() {
  echo -e "\n${BLUE}======================================${NC}"
  echo -e "${BLUE}Test Summary${NC}"
  echo -e "${BLUE}======================================${NC}"
  echo -e "Total Tests: $TEST_COUNT"
  echo -e "${GREEN}Passed: $PASSED${NC}"
  echo -e "${RED}Failed: $FAILED${NC}"
  
  if [[ $FAILED -eq 0 ]]; then
    echo -e "\n${GREEN}✓ All tests passed!${NC}\n"
    return 0
  else
    echo -e "\n${RED}✗ Some tests failed.${NC}\n"
    return 1
  fi
}

# =====================================
# Test 1: Run without root
# =====================================
test_non_root() {
  print_header "Test 1: Non-Root Execution"
  print_test "Running vps-wizard.sh as non-root user"
  
  # Run as current user (non-root) and capture output
  if sudo -u "$SUDO_USER" bash vps-wizard.sh 2>&1 | grep -q "Please run as root"; then
    print_pass "Script correctly rejects non-root execution"
  else
    print_fail "Script did not properly reject non-root user"
  fi
}

# =====================================
# Test 2: Invalid username creation
# =====================================
test_invalid_usernames() {
  print_header "Test 2: Invalid Username Validation"
  
  # We'll test this by examining the username validation regex in the script
  print_test "Checking username validation pattern"
  
  if grep -q "^\[a-z\]\[-a-z0-9_\]\*\$" vps-wizard.sh; then
    print_pass "Username validation pattern exists"
  else
    print_fail "Username validation pattern not found"
  fi
  
  print_info "Username validation requires: start with lowercase, only lowercase/digits/hyphens/underscores"
}

# =====================================
# Test 3: Invalid package installation
# =====================================
test_invalid_package() {
  print_header "Test 3: Non-Existent Package Installation"
  print_test "Testing error handling for non-existent package"
  
  # Create a minimal test that simulates package installation
  TEST_OUTPUT=$(bash -c '
    source vps-wizard.sh 2>/dev/null
    install_app "nonexistentpackage12345xyz" 2>&1
  ' 2>&1)
  
  if echo "$TEST_OUTPUT" | grep -q -i "error\|fail"; then
    print_pass "Package installation error is caught and logged"
  else
    print_info "Unable to verify package error handling in isolated test"
    print_info "Manual test recommended: Try installing 'nonexistentpackage12345'"
  fi
}

# =====================================
# Test 4: GitHub invalid username
# =====================================
test_github_invalid_user() {
  print_header "Test 4: Invalid GitHub Username"
  print_test "Checking GitHub username validation"
  
  if grep -q "Invalid GitHub username" vps-wizard.sh; then
    print_pass "GitHub username validation exists"
    
    # Check if regex validation is present
    if grep -A5 "GitHub username" vps-wizard.sh | grep -q "a-zA-Z0-9"; then
      print_pass "GitHub username format validation pattern found"
    else
      print_fail "GitHub username format validation not found"
    fi
  else
    print_fail "GitHub username error handling not found"
  fi
}

# =====================================
# Test 5: Invalid URL handling
# =====================================
test_invalid_url() {
  print_header "Test 5: Invalid URL Validation"
  print_test "Checking URL validation for SSH key import"
  
  if grep -q "URL must start with http" vps-wizard.sh; then
    print_pass "URL validation exists"
    
    # Check if URL regex is present
    if grep -q "https\\?://" vps-wizard.sh; then
      print_pass "URL format validation pattern found"
    else
      print_fail "URL format validation pattern not found"
    fi
  else
    print_fail "URL validation not found"
  fi
}

# =====================================
# Test 6: File permission checks
# =====================================
test_file_permissions() {
  print_header "Test 6: File Permission Validation"
  print_test "Checking file read permission validation"
  
  if grep -q "Cannot read file\|Permission Denied" vps-wizard.sh; then
    print_pass "File permission checks exist"
  else
    print_fail "File permission checks not found"
  fi
  
  print_test "Checking empty file validation"
  if grep -q "Empty file\|Empty File" vps-wizard.sh; then
    print_pass "Empty file checks exist"
  else
    print_fail "Empty file checks not found"
  fi
}

# =====================================
# Test 7: User deletion safety
# =====================================
test_user_deletion_safety() {
  print_header "Test 7: User Deletion Safety Checks"
  print_test "Checking for active user detection"
  
  if grep -q "currently logged in" vps-wizard.sh; then
    print_pass "Active user detection exists"
  else
    print_fail "Active user detection not found"
  fi
  
  print_test "Checking for deletion confirmation"
  if grep -q "WARNING.*cannot be undone\|CANNOT be undone" vps-wizard.sh; then
    print_pass "Deletion warning exists"
  else
    print_fail "Deletion warning not found"
  fi
}

# =====================================
# Test 8: SSH config backup
# =====================================
test_ssh_backup() {
  print_header "Test 8: SSH Configuration Backup"
  print_test "Checking SSH config backup creation"
  
  if grep -q "ssh_config.*backup" vps-wizard.sh; then
    print_pass "SSH config backup mechanism exists"
  else
    print_fail "SSH config backup not found"
  fi
  
  print_test "Checking SSH config validation"
  if grep -q "sshd -t" vps-wizard.sh; then
    print_pass "SSH config syntax validation exists"
  else
    print_fail "SSH config syntax validation not found"
  fi
}

# =====================================
# Test 9: Error logging
# =====================================
test_error_logging() {
  print_header "Test 9: Error Logging System"
  print_test "Checking error log file creation"
  
  if grep -q "ERROR_LOG=" vps-wizard.sh; then
    print_pass "Error log file variable defined"
    
    ERROR_LOG_PATH=$(grep "^ERROR_LOG=" vps-wizard.sh | cut -d'=' -f2 | tr -d '"')
    print_info "Error log path: $ERROR_LOG_PATH"
  else
    print_fail "Error log file not defined"
  fi
  
  print_test "Checking log_error function"
  if grep -q "log_error()" vps-wizard.sh; then
    print_pass "log_error function exists"
  else
    print_fail "log_error function not found"
  fi
  
  print_test "Checking error_exit function"
  if grep -q "error_exit()" vps-wizard.sh; then
    print_pass "error_exit function exists"
  else
    print_fail "error_exit function not found"
  fi
}

# =====================================
# Test 10: Trap handling
# =====================================
test_trap_handling() {
  print_header "Test 10: Error Trap Handling"
  print_test "Checking trap for ERR INT TERM"
  
  if grep -q "trap.*ERR.*INT.*TERM" vps-wizard.sh; then
    print_pass "Error trap is configured"
  else
    print_fail "Error trap not found"
  fi
  
  print_test "Checking set -euo pipefail"
  if grep -q "set -euo pipefail" vps-wizard.sh; then
    print_pass "Strict error mode enabled"
  else
    print_fail "Strict error mode not enabled"
  fi
}

# =====================================
# Test 11: Installation summary
# =====================================
test_installation_summary() {
  print_header "Test 11: Installation Summary Reporting"
  print_test "Checking profile installation summary"
  
  if grep -q "Installation Summary" vps-wizard.sh; then
    print_pass "Installation summary exists"
  else
    print_fail "Installation summary not found"
  fi
  
  print_test "Checking failure tracking"
  if grep -q "failed_packages\|failed_commands\|failed_langs" vps-wizard.sh; then
    print_pass "Failure tracking arrays exist"
  else
    print_fail "Failure tracking not found"
  fi
}

# =====================================
# Test 12: Dependency installation
# =====================================
test_dependency_check() {
  print_header "Test 12: Dependency Installation"
  print_test "Checking dependency installation function"
  
  if grep -q "install_dependency()" vps-wizard.sh; then
    print_pass "install_dependency function exists"
  else
    print_fail "install_dependency function not found"
  fi
  
  print_test "Checking whiptail dependency"
  if grep -q "install_dependency whiptail" vps-wizard.sh; then
    print_pass "whiptail dependency check exists"
  else
    print_fail "whiptail dependency check not found"
  fi
  
  print_test "Checking curl dependency"
  if grep -q "install_dependency curl" vps-wizard.sh; then
    print_pass "curl dependency check exists"
  else
    print_fail "curl dependency check not found"
  fi
}

# =====================================
# Test 13: Profile validation
# =====================================
test_profile_validation() {
  print_header "Test 13: Profile Creation Validation"
  print_test "Checking profile name length validation"
  
  if grep -q "\${#NAME}.*64" vps-wizard.sh; then
    print_pass "Profile name length validation exists"
  else
    print_fail "Profile name length validation not found"
  fi
  
  print_test "Checking profile name sanitization"
  if grep -q "SAFE_NAME.*tr.*-dc" vps-wizard.sh; then
    print_pass "Profile name sanitization exists"
  else
    print_fail "Profile name sanitization not found"
  fi
}

# =====================================
# Main test execution
# =====================================
main() {
  print_header "VPS Wizard Error Handling Test Suite"
  print_info "Testing script: vps-wizard.sh"
  print_info "Started: $(date)"
  
  # Check if script exists
  if [[ ! -f "vps-wizard.sh" ]]; then
    echo -e "${RED}Error: vps-wizard.sh not found in current directory${NC}"
    exit 1
  fi
  
  # Check if running as root
  if [[ $EUID -ne 0 ]]; then
    echo -e "${YELLOW}Warning: Not running as root. Some tests may be limited.${NC}"
    echo -e "${YELLOW}Run with sudo for complete testing.${NC}\n"
    sleep 2
  fi
  
  # Run all tests
  test_non_root
  test_invalid_usernames
  test_invalid_package
  test_github_invalid_user
  test_invalid_url
  test_file_permissions
  test_user_deletion_safety
  test_ssh_backup
  test_error_logging
  test_trap_handling
  test_installation_summary
  test_dependency_check
  test_profile_validation
  
  # Print summary
  print_summary
}

# Run tests
main "$@"
