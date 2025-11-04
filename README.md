# VPS Wizard

An interactive VPS provisioning script with comprehensive error handling and user management capabilities.

## Features

- **Interactive Setup**: User-friendly whiptail-based TUI
- **Comprehensive Error Handling**: Production-ready with detailed logging
- **User Management**: Create, edit, delete users with advanced options
- **SSH Hardening**: Secure SSH configuration with backup and validation
- **Profile System**: Reusable installation profiles for common setups
- **Package Management**: Install applications with dependency tracking
- **SSH Key Management**: Import keys from GitHub, URLs, or local files
- **Activity Monitoring**: View user login history and failed attempts

## Quick Start

```bash
# Clone the repository
git clone https://github.com/d0773d/vps-wizard.git
cd vps-wizard

# Make the script executable
chmod +x vps-wizard.sh

# Run as root
sudo ./vps-wizard.sh
```

## Requirements

- Ubuntu/Debian-based system
- Root access (sudo)
- Basic utilities: whiptail, curl

## Testing

The repository includes comprehensive test scripts:

```bash
# Quick automated verification
sudo ./final-test.sh

# Static code verification
sudo ./verify-errors.sh

# Manual test scenarios
cat MANUAL_TEST_GUIDE.md
```

## Error Handling

The script features production-grade error handling:

- Strict mode (`set -euo pipefail`)
- Dual logging system (main log + error log)
- Graceful handling of missing commands
- Input validation for usernames, URLs, and GitHub usernames
- SSH configuration backup and validation
- Failure tracking for batch operations

## Logs

- Main log: `/var/log/vps-setup.log`
- Error log: `/var/log/vps-setup-errors.log`

## Profile System

Profiles are stored in `/etc/vps-wizard/profiles.d/` and can include:
- APT packages
- Custom commands
- Programming languages
- Environment setup

## License

MIT License - feel free to use and modify as needed.

## Contributing

Contributions welcome! Please test thoroughly using the provided test scripts.
