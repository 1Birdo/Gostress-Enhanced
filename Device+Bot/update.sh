#!/bin/bash

# Enhanced Bot Update Script
# Usage: ./update.sh /path/to/current/bot

# Configuration
CURRENT_BOT="$1"
BOT_DIR=$(dirname "$1")
BOT_NAME=$(basename "$1")
NEW_BOT="$BOT_NAME.new"
BACKUP_BOT="$BOT_NAME.bak"
UPDATE_LOG="/var/log/bot_update.log"
DOWNLOAD_URL="http://localhost:8000/bot"  # Change this to your actual download URL
MAX_RETRIES=4
RETRY_DELAY=5

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $UPDATE_LOG
}

# Verify we got the current bot path
if [ -z "$1" ]; then
    log "Error: Please provide the current bot path as argument"
    exit 1
fi

log "=== Starting Bot Update ==="
log "Current bot: $CURRENT_BOT"

# 1. Download new version with retries
download_success=false
for ((i=1; i<=$MAX_RETRIES; i++)); do
    log "Download attempt $i of $MAX_RETRIES..."
    if wget -q "$DOWNLOAD_URL" -O "$NEW_BOT"; then
        download_success=true
        break
    fi
    sleep $RETRY_DELAY
done

if [ "$download_success" != "true" ]; then
    log "Error: Failed to download new version after $MAX_RETRIES attempts"
    exit 1
fi

# Make new binary executable
if ! chmod +x "$NEW_BOT"; then
    log "Error: Failed to make new binary executable"
    exit 1
fi

# 2. Verify the new binary
if ! "$NEW_BOT" --version &>/dev/null; then
    log "Error: New binary verification failed"
    rm -f "$NEW_BOT"
    exit 1
fi

# 3. Stop current bot
log "Stopping current bot..."
pkill -f "$BOT_NAME"

# Wait for shutdown (10 seconds max)
for i in {1..10}; do
    if ! pgrep -f "$BOT_NAME" >/dev/null; then
        break
    fi
    sleep 1
done

# Force kill if still running
if pgrep -f "$BOT_NAME" >/dev/null; then
    log "Warning: Force killing bot process"
    pkill -9 -f "$BOT_NAME"
fi

# 4. Create backup
log "Creating backup..."
if ! mv "$CURRENT_BOT" "$BACKUP_BOT"; then
    log "Warning: Failed to create backup"
fi

# 5. Install new version
log "Installing new version..."
if ! mv "$NEW_BOT" "$CURRENT_BOT"; then
    log "Error: Failed to install new version"
    # Attempt to restore from backup
    if [ -f "$BACKUP_BOT" ]; then
        log "Attempting to restore from backup..."
        mv "$BACKUP_BOT" "$CURRENT_BOT"
    fi
    exit 1
fi

# 6. Restart bot
log "Restarting bot..."
cd "$BOT_DIR" || exit 1
nohup "./$BOT_NAME" >/dev/null 2>&1 &

# Verify the bot is running
sleep 2
if ! pgrep -f "$BOT_NAME" >/dev/null; then
    log "Error: Bot failed to start after update"
    # Attempt to restore from backup and restart
    if [ -f "$BACKUP_BOT" ]; then
        log "Attempting to restore from backup and restart..."
        mv "$BACKUP_BOT" "$CURRENT_BOT"
        nohup "./$BOT_NAME" >/dev/null 2>&1 &
    fi
    exit 1
fi

log "=== Update Completed Successfully ==="
exit 0