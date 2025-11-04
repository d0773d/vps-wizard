#!/bin/bash
# =====================================
# VPS Setup Wizard v5 — Full Version
# Features:
# - Root check & logging
# - System update, user creation, SSH hardening
# - Built-in & custom profiles (categories)
# - APT packages + custom commands
# - Profile creation wizard with categories + languages
# - Programming language selection (manual & per-profile)
# - User editor / management dashboard
#   - normal/all users toggle
#   - create/delete users
#   - sudo, shell, lock/unlock
#   - advanced details (comment, home dir, disk usage)
#   - user activity viewer (+ optional export)
#   - SSH key manager (preview, edit, import, dedupe, delete by line)
# =====================================

set -euo pipefail  # Exit on error, undefined vars, pipe failures
LOG_FILE="/var/log/vps-setup.log"
PROFILE_DIR="/etc/vps-wizard/profiles.d"
ERROR_LOG="/var/log/vps-setup-errors.log"

# --- Error handling setup ---
error_exit() {
  local msg="$1"
  local code="${2:-1}"
  echo "[ERROR $(date '+%Y-%m-%d %H:%M:%S')] $msg" | tee -a "$ERROR_LOG" >&2
  whiptail --title "Error" --msgbox "❌ Error: $msg\n\nCheck $ERROR_LOG for details." 12 70 2>/dev/null || echo "Error: $msg"
  exit "$code"
}

trap 'error_exit "Script interrupted or failed at line $LINENO" $?' ERR INT TERM

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
  error_exit "Please run as root (use sudo)." 1
fi

# --- Dependencies ---
install_dependency() {
  local pkg="$1"
  if ! command -v "$pkg" &>/dev/null; then
    echo "Installing dependency: $pkg..."
    if ! apt update &>/dev/null; then
      error_exit "Failed to update package lists. Check your internet connection."
    fi
    if ! apt install -y "$pkg" &>/dev/null; then
      error_exit "Failed to install required dependency: $pkg"
    fi
    echo "✓ $pkg installed successfully"
  fi
}

install_dependency whiptail
install_dependency curl

# --- Setup logging ---
if ! mkdir -p "$PROFILE_DIR" 2>/dev/null; then
  error_exit "Failed to create profile directory: $PROFILE_DIR"
fi

if ! touch "$LOG_FILE" "$ERROR_LOG" 2>/dev/null; then
  error_exit "Failed to create log files in /var/log/"
fi

chmod 600 "$LOG_FILE" "$ERROR_LOG" 2>/dev/null || error_exit "Failed to set log file permissions"

exec > >(tee -a "$LOG_FILE") 2>&1

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_error() { echo "[ERROR $(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$ERROR_LOG" >&2; }

run_with_progress() {
  local title="$1"
  local cmd="$2"
  local temp_log=$(mktemp)
  
  log "Running: $cmd"
  
  (
    if eval "$cmd" >"$temp_log" 2>&1 & then
      PID=$!
      while kill -0 $PID 2>/dev/null; do
        echo 50
        sleep 1
      done
      wait $PID
      EXIT_CODE=$?
      echo 100
      
      if [ $EXIT_CODE -ne 0 ]; then
        log_error "Command failed with exit code $EXIT_CODE: $cmd"
        log_error "Output: $(cat "$temp_log")"
        rm -f "$temp_log"
        return $EXIT_CODE
      fi
      rm -f "$temp_log"
      return 0
    else
      log_error "Failed to start command: $cmd"
      rm -f "$temp_log"
      return 1
    fi
  ) | whiptail --gauge "$title..." 8 60 0
  
  return ${PIPESTATUS[0]}
}

msg() { whiptail --title "$1" --msgbox "$2" 10 60; }

install_app() {
  local app="$1"
  
  # Validate package name
  if [[ -z "$app" ]]; then
    log_error "install_app called with empty package name"
    msg "Error" "Invalid package name provided."
    return 1
  fi
  
  log "Installing package(s): $app"
  
  if ! run_with_progress "Installing $app" "apt install -y $app"; then
    log_error "Failed to install package: $app"
    msg "Installation Failed" "Failed to install: $app\n\nCheck $ERROR_LOG for details."
    return 1
  fi
  
  log "Successfully installed: $app"
  return 0
}

run_custom_command() {
  local cmd="$1"
  
  if [[ -z "$cmd" ]]; then
    log_error "run_custom_command called with empty command"
    return 1
  fi
  
  log "Executing custom command: $cmd"
  
  if ! run_with_progress "Running custom command" "$cmd"; then
    log_error "Custom command failed: $cmd"
    msg "Command Failed" "Failed to execute custom command.\n\nCheck $ERROR_LOG for details."
    return 1
  fi
  
  log "Custom command completed successfully"
  return 0
}

# --- Base setup ---
update_system() {
  log "Starting system update..."
  
  if ! run_with_progress "Updating package lists" "apt update -y"; then
    msg "Update Failed" "Failed to update package lists.\n\nPlease check your internet connection and repository configuration."
    return 1
  fi
  
  if ! run_with_progress "Upgrading packages" "apt upgrade -y"; then
    msg "Upgrade Warning" "Package upgrade encountered errors.\n\nSome packages may not have been updated."
    return 1
  fi
  
  log "System update completed successfully"
  msg "Success" "System updated successfully!"
  return 0
}

create_user() {
  USERNAME=$(whiptail --inputbox "Enter the new username:" 10 60 3>&1 1>&2 2>&3)
  
  if [[ -z "$USERNAME" ]]; then
    log "User creation canceled - no username provided"
    msg "Canceled" "No username entered. User creation canceled."
    return 1
  fi
  
  # Validate username format
  if [[ ! "$USERNAME" =~ ^[a-z][-a-z0-9_]*$ ]]; then
    log_error "Invalid username format: $USERNAME"
    msg "Invalid Username" "Username must start with a lowercase letter and contain only lowercase letters, digits, hyphens, and underscores."
    return 1
  fi
  
  # Check if username is too long
  if [[ ${#USERNAME} -gt 32 ]]; then
    log_error "Username too long: $USERNAME (${#USERNAME} chars)"
    msg "Invalid Username" "Username must be 32 characters or less."
    return 1
  fi

  if id "$USERNAME" &>/dev/null; then
    log_error "User already exists: $USERNAME"
    msg "User Exists" "User '$USERNAME' already exists!"
    return 1
  fi

  log "Creating user: $USERNAME"
  
  if ! run_with_progress "Creating user $USERNAME" "adduser --gecos '' --disabled-password $USERNAME"; then
    log_error "Failed to create user: $USERNAME"
    msg "Creation Failed" "Failed to create user '$USERNAME'.\n\nCheck $ERROR_LOG for details."
    return 1
  fi

  if whiptail --yesno "Add '$USERNAME' to sudo group?" 10 60; then
    if usermod -aG sudo "$USERNAME" 2>/dev/null; then
      log "Added $USERNAME to sudo group"
    else
      log_error "Failed to add $USERNAME to sudo group"
      msg "Warning" "Failed to add user to sudo group."
    fi
  fi

  if whiptail --yesno "Set a password for '$USERNAME' now?" 10 60; then
    if passwd "$USERNAME"; then
      log "Password set for user: $USERNAME"
    else
      log_error "Password setting failed for: $USERNAME"
      msg "Warning" "Failed to set password. You can set it later."
    fi
  fi

  log "User created successfully: $USERNAME"
  msg "User Created" "User '$USERNAME' created successfully."
  return 0
}

secure_ssh() {
  local ssh_config="/etc/ssh/sshd_config"
  
  # Check if SSH config exists
  if [[ ! -f "$ssh_config" ]]; then
    log_error "SSH config file not found: $ssh_config"
    msg "Error" "SSH configuration file not found.\n\nIs OpenSSH server installed?"
    return 1
  fi
  
  # Backup SSH config
  local backup="${ssh_config}.backup.$(date +%Y%m%d-%H%M%S)"
  if ! cp "$ssh_config" "$backup" 2>/dev/null; then
    log_error "Failed to backup SSH config"
    msg "Warning" "Could not create backup of SSH config.\n\nContinue anyway?"
    if ! whiptail --yesno "Proceed without backup?" 10 60; then
      return 1
    fi
  else
    log "SSH config backed up to: $backup"
  fi
  
  log "Configuring SSH security settings..."
  
  # Disable root login
  if ! sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' "$ssh_config" 2>/dev/null; then
    log_error "Failed to modify SSH config"
    msg "Error" "Failed to modify SSH configuration."
    return 1
  fi
  
  # Validate SSH config
  if ! sshd -t 2>/dev/null; then
    log_error "Invalid SSH configuration after changes"
    msg "Error" "SSH configuration is invalid.\n\nRestoring backup..."
    if [[ -f "$backup" ]]; then
      cp "$backup" "$ssh_config"
      log "SSH config restored from backup"
    fi
    return 1
  fi
  
  # Restart SSH service
  if ! systemctl restart ssh 2>/dev/null && ! systemctl restart sshd 2>/dev/null; then
    log_error "Failed to restart SSH service"
    msg "Error" "Failed to restart SSH service.\n\nChanges made but not applied."
    return 1
  fi
  
  log "SSH secured successfully"
  msg "SSH Secured" "✓ Root login disabled in SSH.\n✓ SSH service restarted.\n\nBackup saved to:\n$backup"
  return 0
}

# --- Built-in profiles ---
builtin_profiles=(
  "1|🌐 Web Server Stack|nginx php certbot fail2ban|Web"
  "2|🐬 Database Server|mariadb-server postgresql fail2ban|Database"
  "3|🐳 Docker Host|docker.io docker-compose ufw|DevOps"
  "4|🧠 Developer Tools|git nodejs vim htop|DevOps"
)

# --- Load custom profiles (NAME|DESC|CATEGORY) into assoc array ---
load_custom_profiles() {
  declare -gA CUSTOM_PROFILES
  CUSTOM_PROFILES=()
  
  # Ensure profile directory exists
  if [[ ! -d "$PROFILE_DIR" ]]; then
    log_error "Profile directory does not exist: $PROFILE_DIR"
    return 1
  fi
  
  local profile_count=0
  for file in "$PROFILE_DIR"/*.profile; do
    [[ -f "$file" ]] || continue
    
    # Check if file is readable
    if [[ ! -r "$file" ]]; then
      log_error "Cannot read profile file: $file"
      continue
    fi
    
    NAME=$(grep '^NAME=' "$file" 2>/dev/null | cut -d'=' -f2-)
    DESC=$(grep '^DESCRIPTION=' "$file" 2>/dev/null | cut -d'=' -f2-)
    CAT=$(grep '^CATEGORY=' "$file" 2>/dev/null | cut -d'=' -f2-)
    
    [[ -z "$CAT" ]] && CAT="Uncategorized"
    
    if [[ -z "$NAME" ]]; then
      log_error "Profile file missing NAME field: $file"
      continue
    fi
    
    CUSTOM_PROFILES["$file"]="$NAME|$DESC|$CAT"
    ((profile_count++))
  done
  
  log "Loaded $profile_count custom profiles"
  return 0
}

# --- Install profile with category selection ---
install_profile() {
  load_custom_profiles

  # Collect categories
  declare -A CATEGORY_MAP
  CATEGORY_MAP=()

  for file in "${!CUSTOM_PROFILES[@]}"; do
    INFO=${CUSTOM_PROFILES[$file]}
    CAT=$(echo "$INFO" | cut -d'|' -f3)
    CATEGORY_MAP["$CAT"]=1
  done

  for entry in "${builtin_profiles[@]}"; do
    IFS='|' read -r num name pkgs cat <<<"$entry"
    CATEGORY_MAP["$cat"]=1
  done

  # Select category
  MENU_ITEMS=()
  for cat in "${!CATEGORY_MAP[@]}"; do
    MENU_ITEMS+=("$cat" "$cat profiles")
  done

  if [[ ${#MENU_ITEMS[@]} -eq 0 ]]; then
    msg "No Profiles" "No profiles or categories found."
    return
  fi

  CATEGORY=$(whiptail --title "Select Category" --menu "Choose a profile category:" 20 70 10 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)
  [[ -z "$CATEGORY" ]] && return

  # Profiles in selected category
  MENU_ITEMS=()
  # Built-in
  for entry in "${builtin_profiles[@]}"; do
    IFS='|' read -r num name pkgs cat <<<"$entry"
    [[ "$cat" != "$CATEGORY" ]] && continue
    MENU_ITEMS+=("$num" "$name - $pkgs")
  done
  # Custom
  for file in "${!CUSTOM_PROFILES[@]}"; do
    INFO=${CUSTOM_PROFILES[$file]}
    NAME=$(echo "$INFO" | cut -d'|' -f1)
    DESC=$(echo "$INFO" | cut -d'|' -f2)
    CAT=$(echo "$INFO" | cut -d'|' -f3)
    [[ "$CAT" != "$CATEGORY" ]] && continue
    MENU_ITEMS+=("$file" "$NAME - $DESC (custom)")
  done

  if [[ ${#MENU_ITEMS[@]} -eq 0 ]]; then
    msg "No Profiles" "No profiles found in category '$CATEGORY'."
    return
  fi

  PROFILE_FILE=$(whiptail --title "Select Profile" --menu "Choose profile to install:" 20 70 10 "${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)
  [[ -z "$PROFILE_FILE" ]] && return

  # --- Read profile contents ---
  APPS=()
  COMMANDS=()
  LANGS=""

  if [[ -f "$PROFILE_FILE" ]]; then
    APPS_STR=$(grep '^APPS=' "$PROFILE_FILE" | cut -d'=' -f2- | tr ',' ' ')
    COMMANDS_STR=$(grep '^COMMANDS=' "$PROFILE_FILE" | cut -d'=' -f2-)
    LANGS=$(grep '^LANGS=' "$PROFILE_FILE" | cut -d'=' -f2-)

    [[ -n "$APPS_STR" ]] && read -r -a APPS <<<"$APPS_STR"
    if [[ -n "$COMMANDS_STR" ]]; then
      IFS=';' read -r -a COMMANDS <<<"$COMMANDS_STR"
      IFS=' '
    fi
  else
    # Built-in
    for entry in "${builtin_profiles[@]}"; do
      IFS='|' read -r num name pkgs cat <<<"$entry"
      if [[ "$num" == "$PROFILE_FILE" ]]; then
        read -r -a APPS <<<"$pkgs"
        break
      fi
    done
  fi

  # Install packages
  local failed_packages=()
  local installed_packages=0
  
  for app in "${APPS[@]}"; do
    if [[ -n "$app" ]]; then
      if install_app "$app"; then
        ((installed_packages++))
      else
        failed_packages+=("$app")
      fi
    fi
  done

  # Run custom commands
  local failed_commands=()
  local executed_commands=0
  
  for cmd in "${COMMANDS[@]}"; do
    if [[ -n "$cmd" ]]; then
      if run_custom_command "$cmd"; then
        ((executed_commands++))
      else
        failed_commands+=("$cmd")
      fi
    fi
  done

  # Per-installation language selection (only if profile defines LANGS)
  local failed_profile_langs=()
  local installed_profile_langs=0
  
  if [[ -n "$LANGS" ]]; then
    IFS=' ' read -r -a LANG_ARRAY <<<"$LANGS"
    MENU_ITEMS=()
    for lang in "${LANG_ARRAY[@]}"; do
      [[ -n "$lang" ]] && MENU_ITEMS+=("$lang" "$lang runtime/tools" ON)
    done

    if [[ ${#MENU_ITEMS[@]} -gt 0 ]]; then
      SELECTED_LANGS=$(whiptail --title "Select Languages to Install" --checklist \
"Choose languages for this profile installation:" 20 70 10 \
"${MENU_ITEMS[@]}" 3>&1 1>&2 2>&3)
      SELECTED_LANGS=$(echo $SELECTED_LANGS | tr -d '"')

      for lang in $SELECTED_LANGS; do
        log "Installing profile language: $lang"
        case "$lang" in
          Python) 
            if install_app "python3 python3-pip python3-venv"; then
              ((installed_profile_langs++))
            else
              failed_profile_langs+=("Python")
            fi
            ;;
          NodeJS) 
            if run_custom_command "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && apt install -y nodejs"; then
              ((installed_profile_langs++))
            else
              failed_profile_langs+=("NodeJS")
            fi
            ;;
          Go) 
            if install_app "golang"; then
              ((installed_profile_langs++))
            else
              failed_profile_langs+=("Go")
            fi
            ;;
          Ruby) 
            if install_app "ruby-full"; then
              ((installed_profile_langs++))
            else
              failed_profile_langs+=("Ruby")
            fi
            ;;
          Java) 
            if install_app "openjdk-17-jdk maven"; then
              ((installed_profile_langs++))
            else
              failed_profile_langs+=("Java")
            fi
            ;;
          Rust) 
            if run_custom_command "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"; then
              ((installed_profile_langs++))
            else
              failed_profile_langs+=("Rust")
            fi
            ;;
          *)
            log_error "Unknown language in profile: $lang"
            failed_profile_langs+=("$lang")
            ;;
        esac
      done
    fi
  fi

  # Generate installation summary
  local summary="Profile Installation Summary\n\n"
  summary+="📦 Packages: $installed_packages installed"
  [[ ${#failed_packages[@]} -gt 0 ]] && summary+=", ${#failed_packages[@]} failed"
  summary+="\n"
  
  if [[ ${#COMMANDS[@]} -gt 0 ]]; then
    summary+="⚙️  Commands: $executed_commands executed"
    [[ ${#failed_commands[@]} -gt 0 ]] && summary+=", ${#failed_commands[@]} failed"
    summary+="\n"
  fi
  
  if [[ $installed_profile_langs -gt 0 ]] || [[ ${#failed_profile_langs[@]} -gt 0 ]]; then
    summary+="🔤 Languages: $installed_profile_langs installed"
    [[ ${#failed_profile_langs[@]} -gt 0 ]] && summary+=", ${#failed_profile_langs[@]} failed"
    summary+="\n"
  fi
  
  # Determine overall status
  local total_failures=$((${#failed_packages[@]} + ${#failed_commands[@]} + ${#failed_profile_langs[@]}))
  
  if [[ $total_failures -eq 0 ]]; then
    log "Profile installation completed successfully"
    msg "✓ Installation Complete" "$summary\nAll items installed successfully!"
  else
    log_error "Profile installation completed with $total_failures failure(s)"
    summary+="\n⚠️  Some items failed to install.\n\nCheck $ERROR_LOG for details."
    msg "⚠️  Partial Success" "$summary"
  fi
}

# --- Create new profile ---
create_profile() {
  NAME=$(whiptail --inputbox "Enter profile name:" 10 60 3>&1 1>&2 2>&3)
  
  if [[ -z "$NAME" ]]; then
    log "Profile creation canceled - no name provided"
    return 1
  fi
  
  # Validate profile name
  if [[ ${#NAME} -gt 64 ]]; then
    msg "Invalid Name" "Profile name must be 64 characters or less."
    return 1
  fi

  DESC=$(whiptail --inputbox "Enter a short description:" 10 60 3>&1 1>&2 2>&3)

  CATEGORY=$(whiptail --title "Profile Category" --menu "Select category:" 20 60 10 \
    "Web" "Web applications / Servers" \
    "DevOps" "DevOps tools / Containers" \
    "Monitoring" "Monitoring & Logging tools" \
    "Security" "Security tools & hardening" \
    "Uncategorized" "No specific category" 3>&1 1>&2 2>&3)
  [[ -z "$CATEGORY" ]] && CATEGORY="Uncategorized"

  APPS=$(whiptail --inputbox "Enter APT packages (comma-separated, optional):" 12 60 3>&1 1>&2 2>&3)
  COMMANDS=$(whiptail --inputbox "Enter custom commands (semicolon-separated, optional):" 12 60 3>&1 1>&2 2>&3)

  LANGS=$(whiptail --title "Programming Languages" --checklist \
"Select languages to include in this profile:" 20 70 10 \
"Python" "Python3 + pip + venv" OFF \
"NodeJS" "Node.js LTS + npm" OFF \
"Go" "Golang compiler" OFF \
"Ruby" "Ruby + gem" OFF \
"Java" "OpenJDK 17 + Maven" OFF \
"Rust" "Rust + cargo via rustup" OFF 3>&1 1>&2 2>&3)
  LANGS=$(echo $LANGS | tr -d '"')

  SAFE_NAME=$(echo "$NAME" | tr ' ' '-' | tr -dc 'A-Za-z0-9-_')
  
  if [[ -z "$SAFE_NAME" ]]; then
    log_error "Profile name sanitization resulted in empty string: $NAME"
    msg "Invalid Name" "Profile name must contain at least one alphanumeric character."
    return 1
  fi
  
  FILE="$PROFILE_DIR/${SAFE_NAME,,}.profile"
  
  # Check if profile already exists
  if [[ -f "$FILE" ]]; then
    if ! whiptail --yesno "Profile '$SAFE_NAME' already exists.\n\nOverwrite?" 10 60; then
      log "Profile creation canceled - file exists: $FILE"
      return 1
    fi
  fi

  log "Creating profile: $NAME -> $FILE"
  
  # Write profile with error checking
  if ! {
    echo "NAME=$NAME"
    echo "DESCRIPTION=$DESC"
    echo "CATEGORY=$CATEGORY"
    [[ -n "$APPS" ]] && echo "APPS=$APPS"
    [[ -n "$COMMANDS" ]] && echo "COMMANDS=$COMMANDS"
    [[ -n "$LANGS" ]] && echo "LANGS=$LANGS"
  } >"$FILE" 2>/dev/null; then
    log_error "Failed to write profile file: $FILE"
    msg "Error" "Failed to save profile.\n\nCheck directory permissions."
    return 1
  fi

  if ! chmod 644 "$FILE" 2>/dev/null; then
    log_error "Failed to set permissions on profile: $FILE"
  fi
  
  log "Profile created successfully: $FILE"
  msg "Profile Saved" "✓ Profile '$NAME' saved as:\n$FILE"
  return 0
}

# --- Manual language installer ---
install_languages() {
  LANGS=$(whiptail --title "Select Programming Languages" --checklist \
"Choose languages to install:" 20 70 10 \
"Python" "Python3 + pip + venv" ON \
"NodeJS" "Node.js LTS + npm" OFF \
"Go" "Golang compiler" OFF \
"Ruby" "Ruby + gem" OFF \
"Java" "OpenJDK 17 + Maven" OFF \
"Rust" "Rust + cargo via rustup" OFF 3>&1 1>&2 2>&3)
  LANGS=$(echo $LANGS | tr -d '"')

  local failed_langs=()
  local success_count=0
  
  for lang in $LANGS; do
    log "Installing language: $lang"
    case "$lang" in
      Python) 
        if install_app "python3 python3-pip python3-venv"; then
          ((success_count++))
        else
          failed_langs+=("Python")
        fi
        ;;
      NodeJS) 
        if run_custom_command "curl -fsSL https://deb.nodesource.com/setup_lts.x | bash - && apt install -y nodejs"; then
          ((success_count++))
        else
          failed_langs+=("NodeJS")
        fi
        ;;
      Go) 
        if install_app "golang"; then
          ((success_count++))
        else
          failed_langs+=("Go")
        fi
        ;;
      Ruby) 
        if install_app "ruby-full"; then
          ((success_count++))
        else
          failed_langs+=("Ruby")
        fi
        ;;
      Java) 
        if install_app "openjdk-17-jdk maven"; then
          ((success_count++))
        else
          failed_langs+=("Java")
        fi
        ;;
      Rust) 
        if run_custom_command "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"; then
          ((success_count++))
        else
          failed_langs+=("Rust")
        fi
        ;;
      *)
        log_error "Unknown language: $lang"
        failed_langs+=("$lang")
        ;;
    esac
  done

  if [[ ${#failed_langs[@]} -eq 0 ]]; then
    log "All $success_count language(s) installed successfully"
    msg "Languages Installed" "✓ All selected programming languages installed successfully!\n\nInstalled: $success_count"
  else
    log_error "Failed to install ${#failed_langs[@]} language(s): ${failed_langs[*]}"
    msg "Partial Success" "Installed: $success_count\nFailed: ${#failed_langs[@]}\n\nFailed languages:\n${failed_langs[*]}\n\nCheck $ERROR_LOG for details."
  fi
}

# --- User Editor / Management Dashboard ---
user_editor() {
  SHOW_SYSTEM=false

  while true; do
    # Determine which users to show
    if [ "$SHOW_SYSTEM" = true ]; then
      USERS=$(awk -F: '$1 != "nobody" {print $1}' /etc/passwd)
      MENU_TITLE="All Users (System + Normal)"
    else
      USERS=$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd)
      MENU_TITLE="Normal Users Only"
    fi

    if [[ -z "$USERS" ]]; then
      msg "No Users" "No users found."
      return
    fi

    MENU_ITEMS=()
    while read -r USER; do
      [[ -z "$USER" ]] && continue
      MENU_ITEMS+=("$USER" "Edit user $USER")
    done <<< "$USERS"

    SELECTED_USER=$(whiptail --title "User Editor" --menu "$MENU_TITLE" 20 70 12 \
      "${MENU_ITEMS[@]}" \
      "CREATE_NEW" "➕ Create new user" \
      "TOGGLE" "🔁 Toggle user view (show/hide system users)" \
      "BACK" "⬅️ Back to main menu" 3>&1 1>&2 2>&3)

    case "$SELECTED_USER" in
      ""|"BACK")
        return
        ;;
      "TOGGLE")
        if [ "$SHOW_SYSTEM" = true ]; then
          SHOW_SYSTEM=false
        else
          SHOW_SYSTEM=true
        fi
        ;;
      "CREATE_NEW")
        create_user
        ;;
      *)
        # Manage selected user
        while true; do
          # Get user info (disable exit-on-error temporarily)
          set +e
          USER_INFO=$(getent passwd "$SELECTED_USER" 2>/dev/null)
          local user_info_result=$?
          set -e
          
          if [[ $user_info_result -ne 0 || -z "$USER_INFO" ]]; then
            msg "Error" "User '$SELECTED_USER' not found."
            break
          fi
          
          HOME_DIR=$(echo "$USER_INFO" | cut -d: -f6)
          SHELL=$(echo "$USER_INFO" | cut -d: -f7)
          COMMENT=$(echo "$USER_INFO" | cut -d: -f5)
          USER_UID=$(echo "$USER_INFO" | cut -d: -f3)
          
          # Get groups safely
          if GROUPS=$(id -nG "$SELECTED_USER" 2>/dev/null); then
            : # Success, GROUPS is set
          else
            GROUPS="N/A"
          fi
          
          # Try lastlog if available, otherwise use last command
          if command -v lastlog &>/dev/null; then
            if LAST_LOGIN=$(lastlog -u "$SELECTED_USER" 2>/dev/null | tail -n 1 | awk '{$1=""; print $0}'); then
              : # Success
            else
              LAST_LOGIN=" Never logged in"
            fi
          else
            if LAST_LOGIN=$(last -n 1 "$SELECTED_USER" 2>/dev/null | head -n 1 | awk '{$1=""; print $0}'); then
              : # Success
            else
              LAST_LOGIN=" Never logged in"
            fi
          fi
          
          # Get disk usage safely
          if DISK_USAGE=$(du -sh "$HOME_DIR" 2>/dev/null | awk '{print $1}'); then
            [[ -z "$DISK_USAGE" ]] && DISK_USAGE="N/A"
          else
            DISK_USAGE="N/A"
          fi
          
          # Check lock status
          if passwd -S "$SELECTED_USER" 2>/dev/null | grep -q "L"; then
            STATUS="🔒 Locked"
          else
            STATUS="✅ Active"
          fi

          INFO_TEXT="\
User: $SELECTED_USER
UID: $USER_UID
Real Name: $COMMENT
Home: $HOME_DIR
Shell: $SHELL
Groups: $GROUPS
Disk Usage: $DISK_USAGE
Last login:$LAST_LOGIN
Status: $STATUS"

          ACTION=$(whiptail --title "Manage User: $SELECTED_USER" --menu "$INFO_TEXT" 25 80 14 \
            "1" "Change password" \
            "2" "Add to sudo group" \
            "3" "Remove from sudo group" \
            "4" "Advanced details →" \
            "5" "Lock account" \
            "6" "Unlock account" \
            "7" "Delete user" \
            "8" "👁️  View user activity" \
            "9" "⬅️ Back to user list" 3>&1 1>&2 2>&3)

          case "$ACTION" in
            1)
              passwd "$SELECTED_USER"
              msg "Password Updated" "Password for '$SELECTED_USER' updated successfully."
              ;;
            2)
              usermod -aG sudo "$SELECTED_USER"
              msg "Sudo Added" "'$SELECTED_USER' is now in sudo group."
              ;;
            3)
              gpasswd -d "$SELECTED_USER" sudo || true
              msg "Sudo Removed" "'$SELECTED_USER' removed from sudo group (if present)."
              ;;
            4)
              # Advanced details submenu
              while true; do
                ADV_ACTION=$(whiptail --title "Advanced Details: $SELECTED_USER" --menu "Select an advanced option:" 22 80 12 \
                  "1" "Edit real name/comment" \
                  "2" "Change home directory" \
                  "3" "Edit login shell" \
                  "4" "View disk usage" \
                  "5" "Manage SSH authorized keys" \
                  "6" "Back" 3>&1 1>&2 2>&3)

                case "$ADV_ACTION" in
                  1)
                    NEW_COMMENT=$(whiptail --inputbox "Enter full name or comment for $SELECTED_USER:" 10 60 "$COMMENT" 3>&1 1>&2 2>&3)
                    if [[ -n "$NEW_COMMENT" ]]; then
                      usermod -c "$NEW_COMMENT" "$SELECTED_USER"
                      msg "Comment Updated" "Updated real name/comment for '$SELECTED_USER'."
                    fi
                    ;;
                  2)
                    NEW_HOME=$(whiptail --inputbox "Enter new home directory for $SELECTED_USER:" 10 60 "$HOME_DIR" 3>&1 1>&2 2>&3)
                    if [[ -n "$NEW_HOME" && "$NEW_HOME" != "$HOME_DIR" ]]; then
                      if whiptail --yesno "Move contents from $HOME_DIR to $NEW_HOME?" 10 60; then
                        usermod -m -d "$NEW_HOME" "$SELECTED_USER"
                      else
                        usermod -d "$NEW_HOME" "$SELECTED_USER"
                      fi
                      msg "Home Directory Updated" "Home directory changed to $NEW_HOME."
                    fi
                    ;;
                  3)
                    NEW_SHELL=$(whiptail --inputbox "Enter new shell (e.g. /bin/bash):" 10 60 "$SHELL" 3>&1 1>&2 2>&3)
                    if [[ -n "$NEW_SHELL" ]]; then
                      chsh -s "$NEW_SHELL" "$SELECTED_USER"
                      msg "Shell Changed" "Shell changed to $NEW_SHELL."
                    fi
                    ;;
                  4)
                    msg "Disk Usage" "Home directory size for '$SELECTED_USER': $DISK_USAGE"
                    ;;
                  5)
                    # SSH authorized keys management
                    AUTH_FILE="$HOME_DIR/.ssh/authorized_keys"

                    # Ensure SSH directory and file exist
                    if [[ ! -d "$HOME_DIR/.ssh" ]]; then
                      mkdir -p "$HOME_DIR/.ssh"
                      chown "$SELECTED_USER":"$SELECTED_USER" "$HOME_DIR/.ssh"
                      chmod 700 "$HOME_DIR/.ssh"
                    fi
                    if [[ ! -f "$AUTH_FILE" ]]; then
                      touch "$AUTH_FILE"
                      chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                      chmod 600 "$AUTH_FILE"
                    fi

                    while true; do
                      PREVIEW=$(head -n 5 "$AUTH_FILE" 2>/dev/null)
                      TOTAL_KEYS=$(grep -c "ssh-" "$AUTH_FILE" 2>/dev/null || echo 0)
                      [[ -z "$PREVIEW" ]] && PREVIEW="(No keys found)"

                      ACTION_KEYS=$(whiptail --title "SSH Keys: $SELECTED_USER" --menu "\
Authorized keys preview (first 5 lines):
──────────────────────────────
$PREVIEW
──────────────────────────────
Total keys: $TOTAL_KEYS

Choose an action:" 25 80 14 \
                        "1" "Edit keys manually" \
                        "2" "Import from GitHub username" \
                        "3" "Import from URL" \
                        "4" "Import from local file" \
                        "5" "Deduplicate keys" \
                        "6" "View & delete key by line number" \
                        "7" "Generate new SSH key pair" \
                        "8" "Back" 3>&1 1>&2 2>&3)

                      case "$ACTION_KEYS" in
                        1)
                          TEMP_FILE=$(mktemp)
                          cp "$AUTH_FILE" "$TEMP_FILE"
                          whiptail --title "Edit SSH Keys for $SELECTED_USER" --editbox "$TEMP_FILE" 25 80 3>&1 1>&2 2>&3 > "$TEMP_FILE"
                          cp "$TEMP_FILE" "$AUTH_FILE"
                          chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                          chmod 600 "$AUTH_FILE"
                          rm -f "$TEMP_FILE"
                          msg "SSH Keys Updated" "Authorized SSH keys updated for '$SELECTED_USER'."
                          ;;
                        2)
                          GH_USER=$(whiptail --inputbox "Enter GitHub username to import keys from:" 10 60 3>&1 1>&2 2>&3)
                          if [[ -n "$GH_USER" ]]; then
                            # Validate GitHub username format
                            if [[ ! "$GH_USER" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
                              msg "Invalid Username" "GitHub username '$GH_USER' appears to be invalid."
                              log_error "Invalid GitHub username format: $GH_USER"
                            else
                              log "Fetching SSH keys from GitHub user: $GH_USER"
                              TEMP_KEYS=$(mktemp)
                              if curl -fsSL "https://github.com/$GH_USER.keys" -o "$TEMP_KEYS" 2>/dev/null; then
                                if [[ -s "$TEMP_KEYS" ]]; then
                                  KEY_COUNT=$(grep -c "ssh-" "$TEMP_KEYS" 2>/dev/null || echo 0)
                                  if [[ $KEY_COUNT -gt 0 ]]; then
                                    cat "$TEMP_KEYS" >> "$AUTH_FILE"
                                    chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                                    chmod 600 "$AUTH_FILE"
                                    log "Imported $KEY_COUNT SSH key(s) from GitHub user: $GH_USER"
                                    msg "GitHub Keys Imported" "✓ Imported $KEY_COUNT SSH key(s) from GitHub user '$GH_USER'."
                                  else
                                    msg "No Keys Found" "No SSH keys found for GitHub user '$GH_USER'."
                                    log_error "No SSH keys found for GitHub user: $GH_USER"
                                  fi
                                else
                                  msg "No Keys" "GitHub user '$GH_USER' has no public keys."
                                  log_error "GitHub user has no keys: $GH_USER"
                                fi
                                rm -f "$TEMP_KEYS"
                              else
                                msg "Error" "Failed to fetch keys for GitHub user '$GH_USER'.\n\nUser may not exist or network error occurred."
                                log_error "Failed to fetch GitHub keys for: $GH_USER"
                                rm -f "$TEMP_KEYS"
                              fi
                            fi
                          fi
                          ;;
                        3)
                          URL=$(whiptail --inputbox "Enter URL to fetch public keys from:" 10 70 3>&1 1>&2 2>&3)
                          if [[ -n "$URL" ]]; then
                            # Basic URL validation
                            if [[ ! "$URL" =~ ^https?:// ]]; then
                              msg "Invalid URL" "URL must start with http:// or https://"
                              log_error "Invalid URL format: $URL"
                            else
                              log "Fetching SSH keys from URL: $URL"
                              TEMP_KEYS=$(mktemp)
                              if curl -fsSL "$URL" -o "$TEMP_KEYS" 2>/dev/null; then
                                if [[ -s "$TEMP_KEYS" ]]; then
                                  cat "$TEMP_KEYS" >> "$AUTH_FILE"
                                  chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                                  chmod 600 "$AUTH_FILE"
                                  log "Imported SSH keys from URL: $URL"
                                  msg "Keys Imported" "✓ Keys imported from:\n$URL"
                                else
                                  msg "Empty Response" "URL returned no content."
                                  log_error "Empty response from URL: $URL"
                                fi
                                rm -f "$TEMP_KEYS"
                              else
                                msg "Error" "Failed to download keys from URL.\n\nCheck the URL and your internet connection."
                                log_error "Failed to fetch keys from URL: $URL"
                                rm -f "$TEMP_KEYS"
                              fi
                            fi
                          fi
                          ;;
                        4)
                          FILE_PATH=$(whiptail --inputbox "Enter path to local .pub / keys file on this server:" 10 70 3>&1 1>&2 2>&3)
                          if [[ -n "$FILE_PATH" ]]; then
                            if [[ -f "$FILE_PATH" ]]; then
                              if [[ -r "$FILE_PATH" ]]; then
                                if [[ -s "$FILE_PATH" ]]; then
                                  log "Importing SSH keys from file: $FILE_PATH"
                                  cat "$FILE_PATH" >> "$AUTH_FILE"
                                  chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                                  chmod 600 "$AUTH_FILE"
                                  msg "Keys Imported" "✓ Keys imported from:\n$FILE_PATH"
                                else
                                  msg "Empty File" "File is empty:\n$FILE_PATH"
                                  log_error "Empty key file: $FILE_PATH"
                                fi
                              else
                                msg "Permission Denied" "Cannot read file:\n$FILE_PATH\n\nCheck file permissions."
                                log_error "Cannot read key file: $FILE_PATH"
                              fi
                            else
                              msg "Error" "File not found:\n$FILE_PATH"
                              log_error "Key file not found: $FILE_PATH"
                            fi
                          fi
                          ;;
                        5)
                          TEMP_FILE=$(mktemp)
                          awk '!seen[$0]++' "$AUTH_FILE" > "$TEMP_FILE"
                          mv "$TEMP_FILE" "$AUTH_FILE"
                          chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                          chmod 600 "$AUTH_FILE"
                          msg "Keys Deduplicated" "Duplicate SSH keys removed for '$SELECTED_USER'."
                          ;;
                        6)
                          TEMP_VIEW=$(mktemp)
                          nl -ba "$AUTH_FILE" > "$TEMP_VIEW"
                          whiptail --title "Per-line View: $SELECTED_USER" --scrolltext --msgbox "Each line below has a number on the left.\nDeleting a line removes that exact line.\n\n$(cat "$TEMP_VIEW")" 30 100
                          TOTAL_LINES=$(wc -l < "$AUTH_FILE")
                          if [[ "$TOTAL_LINES" -eq 0 ]]; then
                            msg "No Lines" "There are no lines to delete in authorized_keys."
                            rm -f "$TEMP_VIEW"
                          else
                            LINE_NUM=$(whiptail --inputbox "Enter the line number to delete (1-$TOTAL_LINES):" 10 60 3>&1 1>&2 2>&3)
                            if [[ -n "$LINE_NUM" ]]; then
                              if [[ "$LINE_NUM" =~ ^[0-9]+$ ]] && [ "$LINE_NUM" -ge 1 ] && [ "$LINE_NUM" -le "$TOTAL_LINES" ]; then
                                sed -i "${LINE_NUM}d" "$AUTH_FILE"
                                chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                                chmod 600 "$AUTH_FILE"
                                msg "Line Deleted" "Deleted line $LINE_NUM from authorized_keys."
                              else
                                msg "Invalid Input" "Line number '$LINE_NUM' is not valid."
                              fi
                            fi
                            rm -f "$TEMP_VIEW"
                          fi
                          ;;
                        7)
                          # Generate new SSH key pair
                          KEY_TYPE=$(whiptail --title "SSH Key Type" --menu "Choose key type:" 15 70 5 \
                            "1" "ed25519 (recommended, modern)" \
                            "2" "rsa 4096 (traditional, widely compatible)" \
                            "3" "ecdsa 521" 3>&1 1>&2 2>&3)
                          
                          KEY_BITS=""
                          case "$KEY_TYPE" in
                            1) KEY_ALGO="ed25519" ;;
                            2) KEY_ALGO="rsa"; KEY_BITS=4096 ;;
                            3) KEY_ALGO="ecdsa"; KEY_BITS=521 ;;
                            *) continue ;;
                          esac
                          
                          KEY_COMMENT=$(whiptail --inputbox "Enter a comment/label for the key (e.g., email or device name):" 10 70 "$SELECTED_USER@$(hostname)" 3>&1 1>&2 2>&3)
                          [[ -z "$KEY_COMMENT" ]] && KEY_COMMENT="$SELECTED_USER@$(hostname)"
                          
                          KEY_NAME=$(whiptail --inputbox "Enter filename for the key pair:" 10 70 "id_${KEY_ALGO}" 3>&1 1>&2 2>&3)
                          [[ -z "$KEY_NAME" ]] && KEY_NAME="id_${KEY_ALGO}"
                          
                          KEY_PATH="$HOME_DIR/.ssh/$KEY_NAME"
                          
                          # Check if key already exists
                          if [[ -f "$KEY_PATH" ]]; then
                            if ! whiptail --yesno "⚠️  Key already exists at:\n$KEY_PATH\n\nOverwrite?" 10 70; then
                              continue
                            fi
                          fi
                          
                          # Ask if key should have a passphrase
                          if whiptail --yesno "Add a passphrase to the private key?\n\n• YES: More secure (requires passphrase to use)\n• NO: Convenient (no passphrase needed)" 12 70; then
                            USE_PASSPHRASE="yes"
                            PASSPHRASE=$(whiptail --passwordbox "Enter passphrase for private key:" 10 70 3>&1 1>&2 2>&3)
                            if [[ -z "$PASSPHRASE" ]]; then
                              msg "Cancelled" "Key generation cancelled - no passphrase provided."
                              continue
                            fi
                          else
                            USE_PASSPHRASE="no"
                            PASSPHRASE=""
                          fi
                          
                          # Generate the key
                          log "Generating SSH key pair for $SELECTED_USER: $KEY_ALGO"
                          
                          if [[ "$USE_PASSPHRASE" == "yes" ]]; then
                            # With passphrase
                            if [[ -n "$KEY_BITS" ]]; then
                              su - "$SELECTED_USER" -c "ssh-keygen -t $KEY_ALGO -b $KEY_BITS -C '$KEY_COMMENT' -f '$KEY_PATH' -N '$PASSPHRASE'" 2>/dev/null
                            else
                              su - "$SELECTED_USER" -c "ssh-keygen -t $KEY_ALGO -C '$KEY_COMMENT' -f '$KEY_PATH' -N '$PASSPHRASE'" 2>/dev/null
                            fi
                          else
                            # Without passphrase
                            if [[ -n "$KEY_BITS" ]]; then
                              su - "$SELECTED_USER" -c "ssh-keygen -t $KEY_ALGO -b $KEY_BITS -C '$KEY_COMMENT' -f '$KEY_PATH' -N ''" 2>/dev/null
                            else
                              su - "$SELECTED_USER" -c "ssh-keygen -t $KEY_ALGO -C '$KEY_COMMENT' -f '$KEY_PATH' -N ''" 2>/dev/null
                            fi
                          fi
                          
                          if [[ -f "$KEY_PATH" && -f "${KEY_PATH}.pub" ]]; then
                            # Set proper permissions
                            chmod 600 "$KEY_PATH"
                            chmod 644 "${KEY_PATH}.pub"
                            chown "$SELECTED_USER":"$SELECTED_USER" "$KEY_PATH" "${KEY_PATH}.pub"
                            
                            # Ask if public key should be added to authorized_keys
                            if whiptail --yesno "✓ SSH key pair generated successfully!\n\nPrivate key: $KEY_PATH\nPublic key: ${KEY_PATH}.pub\n\nAdd the public key to authorized_keys for this user?" 14 80; then
                              cat "${KEY_PATH}.pub" >> "$AUTH_FILE"
                              chown "$SELECTED_USER":"$SELECTED_USER" "$AUTH_FILE"
                              chmod 600 "$AUTH_FILE"
                              log "Added generated public key to authorized_keys for $SELECTED_USER"
                              
                              PUB_KEY_CONTENT=$(cat "${KEY_PATH}.pub")
                              whiptail --title "SSH Key Generated & Added" --msgbox "✓ Key pair generated and public key added to authorized_keys!\n\nPrivate key: $KEY_PATH\nPublic key: ${KEY_PATH}.pub\n\n⚠️  IMPORTANT:\n• Download the PRIVATE key to your local machine\n• Keep it secure - anyone with this key can access the account\n• You can view the public key anytime: cat ${KEY_PATH}.pub\n\nPublic key:\n$PUB_KEY_CONTENT" 24 100
                            else
                              PUB_KEY_CONTENT=$(cat "${KEY_PATH}.pub")
                              whiptail --title "SSH Key Generated" --msgbox "✓ Key pair generated successfully!\n\nPrivate key: $KEY_PATH\nPublic key: ${KEY_PATH}.pub\n\n⚠️  IMPORTANT:\n• Download the PRIVATE key to your local machine\n• Keep it secure\n• Add the public key to authorized_keys when ready\n\nPublic key:\n$PUB_KEY_CONTENT" 22 100
                            fi
                            
                            log "SSH key pair generated for $SELECTED_USER: $KEY_PATH"
                          else
                            msg "Generation Failed" "Failed to generate SSH key pair.\n\nCheck $ERROR_LOG for details."
                            log_error "SSH key generation failed for $SELECTED_USER"
                          fi
                          ;;
                        8|"")
                          break
                          ;;
                      esac
                    done
                    ;;
                  6)
                    break
                    ;;
                esac
              done
              ;;
            5)
              usermod -L "$SELECTED_USER"
              msg "Account Locked" "'$SELECTED_USER' account locked."
              ;;
            6)
              usermod -U "$SELECTED_USER"
              msg "Account Unlocked" "'$SELECTED_USER' account unlocked."
              ;;
            7)
              if whiptail --yesno "⚠️  WARNING ⚠️\n\nAre you sure you want to delete '$SELECTED_USER' and their home directory?\n\nThis action CANNOT be undone!" 12 70; then
                log "Attempting to delete user: $SELECTED_USER"
                
                # Check if user is currently logged in
                if who | grep -q "^$SELECTED_USER "; then
                  msg "User Active" "User '$SELECTED_USER' is currently logged in.\n\nPlease log them out first."
                  log_error "Cannot delete active user: $SELECTED_USER"
                else
                  if deluser --remove-home "$SELECTED_USER" 2>/dev/null; then
                    log "User deleted successfully: $SELECTED_USER"
                    msg "User Deleted" "✓ User '$SELECTED_USER' and their home directory have been deleted."
                    break
                  else
                    log_error "Failed to delete user: $SELECTED_USER"
                    msg "Deletion Failed" "Failed to delete user '$SELECTED_USER'.\n\nThe user may be in use or have running processes.\n\nCheck $ERROR_LOG for details."
                  fi
                fi
              fi
              ;;
            8)
              # Get login activity safely
              if command -v last &>/dev/null; then
                if LAST_LOGINS=$(last -n 10 "$SELECTED_USER" 2>/dev/null | head -n 10); then
                  LOGIN_COUNT=$(echo "$LAST_LOGINS" | grep -vc '^$' || echo "0")
                else
                  LAST_LOGINS="(last command failed)"
                  LOGIN_COUNT="0"
                fi
              else
                LAST_LOGINS="(last command not available - install util-linux)"
                LOGIN_COUNT="N/A"
              fi
              
              # Get failed logins safely
              if [[ -r /var/log/auth.log ]]; then
                if FAILED_LOGINS=$(grep "Failed password for $SELECTED_USER" /var/log/auth.log 2>/dev/null | tail -n 10); then
                  FAIL_COUNT=$(echo "$FAILED_LOGINS" | grep -vc '^$' || echo "0")
                  [[ -z "$FAILED_LOGINS" ]] && FAILED_LOGINS="(no failed login attempts found)"
                else
                  FAILED_LOGINS="(no failed login attempts found)"
                  FAIL_COUNT="0"
                fi
              else
                FAILED_LOGINS="(/var/log/auth.log not accessible)"
                FAIL_COUNT="N/A"
              fi

              ACTIVITY_REPORT="=== Login Activity for $SELECTED_USER ===

Total successful logins (shown): $LOGIN_COUNT
Total failed logins (shown): $FAIL_COUNT

Recent successful logins:
$LAST_LOGINS

Recent failed login attempts:
$FAILED_LOGINS
"
              whiptail --title "User Activity: $SELECTED_USER" --scrolltext --msgbox "$ACTIVITY_REPORT" 30 100

              if whiptail --yesno "Save this activity report to /root/user-reports/ ?" 10 70; then
                mkdir -p /root/user-reports
                TS=$(date '+%Y%m%d-%H%M%S')
                OUT="/root/user-reports/${SELECTED_USER}_activity_$TS.log"
                echo "$ACTIVITY_REPORT" > "$OUT"
                msg "Report Saved" "Activity report saved to:\n$OUT"
              fi
              ;;
            9)
              break
              ;;
            "")
              # Cancel pressed - break inner loop to return to user list
              break
              ;;
            *)
              # Unknown option - show error and continue
              msg "Error" "Unknown option selected."
              ;;
          esac
        done
        ;;
    esac
  done
}

# --- Main menu ---
main_menu() {
  while true; do
    CHOICE=$(whiptail --title "VPS Setup Wizard v5" --menu "Select an action:" 20 70 10 \
      "1" "Update system" \
      "2" "Create user" \
      "3" "Secure SSH" \
      "4" "Install from profile" \
      "5" "Create new profile" \
      "6" "Install Developer Languages" \
      "7" "User editor / manager" \
      "8" "Exit" 3>&1 1>&2 2>&3)

    case "$CHOICE" in
      1) update_system ;;
      2) create_user ;;
      3) secure_ssh ;;
      4) install_profile ;;
      5) create_profile ;;
      6) install_languages ;;
      7) user_editor ;;
      8)
        msg "Exit" "Goodbye! Log saved to $LOG_FILE"
        exit 0
        ;;
      *) ;;
    esac
  done
}

log "===== VPS Setup Wizard v5 Started ====="
log "Log file: $LOG_FILE"
log "Error log: $ERROR_LOG"
log "Profile directory: $PROFILE_DIR"
main_menu