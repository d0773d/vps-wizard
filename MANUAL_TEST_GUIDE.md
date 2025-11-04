# VPS Wizard - Manual Error Handling Test Guide
# ==============================================

This guide walks you through testing all error handling scenarios.
Each test should be performed interactively.

## Prerequisites
- VPS or Linux system with sudo access
- Terminal access

---

## Test 1: Root Permission Check
**Expected: Script should refuse to run without root**

```bash
# Run without sudo (should fail)
./vps-wizard.sh
```

**Expected Output:**
- Error message: "Please run as root (use sudo)"
- Script exits with error code 1
- Error logged to /var/log/vps-setup-errors.log

✅ PASS if script refuses to run  
❌ FAIL if script continues

---

## Test 2: Invalid Username Format
**Expected: Script should reject invalid usernames**

```bash
sudo ./vps-wizard.sh
# Select: Create user
# Try these invalid usernames:
```

| Username | Expected Result |
|----------|----------------|
| `123user` | ❌ Must start with letter |
| `User` | ❌ Must be lowercase |
| `user@name` | ❌ No special chars (except - _) |
| `a` | ✅ Should work (single char OK) |
| `this-is-a-very-long-username-over-32-chars` | ❌ Too long |

✅ PASS if all invalid names are rejected  
❌ FAIL if any invalid name is accepted

---

## Test 3: Duplicate User Creation
**Expected: Script should prevent duplicate users**

```bash
sudo ./vps-wizard.sh
# Select: Create user
# Enter: testuser
# (Complete creation)
# Try again with same name: testuser
```

**Expected:**
- Error message: "User 'testuser' already exists!"
- No duplicate created

✅ PASS if duplicate prevented  
❌ FAIL if allows duplicate

---

## Test 4: Non-existent Package Installation
**Expected: Script should handle missing packages gracefully**

```bash
sudo ./vps-wizard.sh
# Select: Create new profile
# Name: test-profile
# Packages: nonexistentpackage123,fake-pkg
# Save and try to install
```

**Expected:**
- Attempt to install
- Show failure for each package
- Display summary with failure count
- Continue without crashing

✅ PASS if handles gracefully  
❌ FAIL if crashes

---

## Test 5: Invalid GitHub Username
**Expected: Script should validate GitHub usernames**

```bash
sudo ./vps-wizard.sh
# Select: User editor
# Select any user
# Advanced details → Manage SSH keys
# Import from GitHub
# Try these usernames:
```

| Username | Expected |
|----------|----------|
| `user@name` | ❌ Invalid format |
| `user with spaces` | ❌ Spaces not allowed |
| `-invalid` | ❌ Can't start with - |
| `invalid-` | ❌ Can't end with - |
| `torvalds` | ✅ Valid (may have keys) |
| `nonexistentuser9999999` | ⚠️ Valid format but no keys |

✅ PASS if validates format  
❌ FAIL if crashes on invalid input

---

## Test 6: Invalid URL for SSH Keys
**Expected: Script should validate URLs**

```bash
sudo ./vps-wizard.sh
# Select: User editor → SSH keys
# Import from URL
# Try these URLs:
```

| URL | Expected |
|-----|----------|
| `not-a-url` | ❌ No protocol |
| `ftp://example.com` | ❌ Only http/https |
| `http://nonexistent.fake.domain` | ⚠️ Valid format but fails to connect |
| `https://github.com/torvalds.keys` | ✅ Should work |

✅ PASS if validates and handles errors  
❌ FAIL if crashes

---

## Test 7: Non-existent File for SSH Keys
**Expected: Script should check file existence**

```bash
sudo ./vps-wizard.sh
# Select: User editor → SSH keys
# Import from file
# Enter: /tmp/nonexistent.pub
```

**Expected:**
- Error: "File not found"
- Returns to menu gracefully

✅ PASS if handles missing file  
❌ FAIL if crashes

---

## Test 8: Delete Active User
**Expected: Script should prevent deleting logged-in users**

```bash
# First, login as testuser in another terminal
ssh testuser@localhost  # or login on another TTY

# Then in main terminal:
sudo ./vps-wizard.sh
# Select: User editor
# Select: testuser
# Select: Delete user
```

**Expected:**
- Script checks if user is logged in
- Shows error: "User is currently logged in"
- Refuses to delete

✅ PASS if prevents deletion  
❌ FAIL if deletes active user

---

## Test 9: SSH Config Backup
**Expected: Script should backup SSH config before modification**

```bash
sudo ./vps-wizard.sh
# Select: Secure SSH

# After completion, check:
ls -la /etc/ssh/sshd_config.backup.*
```

**Expected:**
- Backup file exists with timestamp
- Original config preserved
- Shows backup location to user

✅ PASS if backup created  
❌ FAIL if no backup

---

## Test 10: Profile with Invalid Commands
**Expected: Script should handle command failures**

```bash
sudo ./vps-wizard.sh
# Create new profile
# Commands: "false; exit 1; nonexistentcommand"
# Install the profile
```

**Expected:**
- Shows each command failure
- Displays summary with failure count
- Doesn't crash script

✅ PASS if handles failures  
❌ FAIL if crashes

---

## Test 11: System Update with No Internet
**Expected: Script should handle network failures**

```bash
# Disconnect internet or:
sudo iptables -A OUTPUT -p tcp --dport 80 -j DROP
sudo iptables -A OUTPUT -p tcp --dport 443 -j DROP

sudo ./vps-wizard.sh
# Select: Update system

# Restore internet:
sudo iptables -F
```

**Expected:**
- Shows error about connection failure
- Suggests checking internet
- Returns to menu

✅ PASS if handles gracefully  
❌ FAIL if hangs or crashes

---

## Test 12: Check Error Logs
**Expected: All errors should be logged**

```bash
# After running tests, check logs:
sudo tail -50 /var/log/vps-setup-errors.log
sudo tail -50 /var/log/vps-setup.log
```

**Expected:**
- Error log contains all failures
- Timestamps present
- Clear error messages
- No sensitive data logged

✅ PASS if logging works  
❌ FAIL if errors not logged

---

## Summary Checklist

| Test # | Description | Status |
|--------|-------------|--------|
| 1 | Root permission check | ☐ |
| 2 | Invalid username format | ☐ |
| 3 | Duplicate user prevention | ☐ |
| 4 | Non-existent package | ☐ |
| 5 | Invalid GitHub username | ☐ |
| 6 | Invalid URL | ☐ |
| 7 | Non-existent file | ☐ |
| 8 | Delete active user | ☐ |
| 9 | SSH config backup | ☐ |
| 10 | Invalid commands | ☐ |
| 11 | Network failure | ☐ |
| 12 | Error logging | ☐ |

---

## Quick Test Commands

```bash
# 1. Test without root
./vps-wizard.sh

# 2. Run main tests
sudo ./vps-wizard.sh

# 3. Check logs
sudo tail -f /var/log/vps-setup-errors.log

# 4. View last test results
sudo grep -A 5 "ERROR" /var/log/vps-setup-errors.log | tail -20
```

---

## Notes
- Keep a terminal open with `sudo tail -f /var/log/vps-setup-errors.log`
- Each test should complete without crashing
- Error messages should be clear and helpful
- Script should always return to menu after errors
