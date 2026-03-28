#!/bin/bash
# GPS Tracker - Production Update Script
# Usage: ssh root@192.168.101.12 '/var/www/gps-tracker-secure/update.sh'
#   or run directly on the production server
#
# This script pulls the latest code from GitHub and restarts the service.
# Database, venv, config, and uploaded images are preserved (git-ignored).

set -euo pipefail

# Configuration
APP_DIR="/var/www/gps-tracker-secure"
SERVICE_NAME="gps-tracker-secure"
SERVICE_USER="gps-tracker"
BACKUP_DIR="/var/www/gps-tracker-secure/backups"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Ensure we're in the app directory
cd "$APP_DIR"

echo -e "${GREEN}=== GPS Tracker Update Script ===${NC}"
echo "App directory: $APP_DIR"
echo "Service: $SERVICE_NAME"
echo ""

# Pre-flight checks
echo -e "${YELLOW}Running pre-flight checks...${NC}"

if ! command -v git &> /dev/null; then
    echo -e "${RED}Error: git is not installed${NC}"
    exit 1
fi

if [ ! -d "$APP_DIR/.git" ]; then
    echo -e "${RED}Error: $APP_DIR is not a git repository${NC}"
    exit 1
fi

echo "  ✅ Git available and repo exists"

# Check for local modifications that would block pull
if ! git diff --quiet 2>/dev/null; then
    echo -e "${YELLOW}  ⚠️  Local modifications detected. Stashing...${NC}"
    git stash
fi

# Backup database before update
echo ""
echo -e "${YELLOW}Backing up database...${NC}"
mkdir -p "$BACKUP_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
if [ -f "$APP_DIR/gps_tracker.db" ]; then
    cp "$APP_DIR/gps_tracker.db" "$BACKUP_DIR/gps_tracker.db.backup-${TIMESTAMP}"
    echo "  ✅ Database backed up to backups/gps_tracker.db.backup-${TIMESTAMP}"
    # Keep only last 10 backups
    ls -t "$BACKUP_DIR"/gps_tracker.db.backup-* 2>/dev/null | tail -n +11 | xargs -r rm
else
    echo "  ℹ️  No database file to backup"
fi

# Pull latest code
echo ""
echo -e "${YELLOW}Pulling latest code from GitHub...${NC}"
BEFORE_HASH=$(git rev-parse HEAD)
git pull origin main
AFTER_HASH=$(git rev-parse HEAD)

if [ "$BEFORE_HASH" = "$AFTER_HASH" ]; then
    echo "  ℹ️  Already up to date (${BEFORE_HASH:0:8})"
else
    echo "  ✅ Updated: ${BEFORE_HASH:0:8} → ${AFTER_HASH:0:8}"
    echo ""
    echo "Changes pulled:"
    git --no-pager log --oneline "${BEFORE_HASH}..${AFTER_HASH}"
fi

# Check if requirements changed and update venv if needed
if git diff "${BEFORE_HASH}..${AFTER_HASH}" --name-only 2>/dev/null | grep -q "requirements.txt"; then
    echo ""
    echo -e "${YELLOW}requirements.txt changed - updating dependencies...${NC}"
    if [ -d "$APP_DIR/venv" ]; then
        "$APP_DIR/venv/bin/pip" install -q -r "$APP_DIR/requirements.txt"
        echo "  ✅ Dependencies updated"
    else
        echo -e "${RED}  ⚠️  No venv found - dependencies not updated${NC}"
    fi
fi

# Fix permissions
echo ""
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
chmod 755 "$APP_DIR"
echo "  ✅ Permissions set"

# Restart service
echo ""
echo -e "${YELLOW}Restarting service...${NC}"
systemctl restart "$SERVICE_NAME"
sleep 2

if systemctl is-active --quiet "$SERVICE_NAME"; then
    echo -e "  ${GREEN}✅ $SERVICE_NAME is running${NC}"
else
    echo -e "  ${RED}❌ $SERVICE_NAME failed to start!${NC}"
    echo "  Check logs: journalctl -u $SERVICE_NAME --no-pager -n 20"
    exit 1
fi

# Health check
echo ""
echo -e "${YELLOW}Running health check...${NC}"
sleep 1
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5001/api/health 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ]; then
    echo -e "  ${GREEN}✅ Application responding (HTTP $HTTP_CODE)${NC}"
else
    echo -e "  ${YELLOW}⚠️  Health check returned HTTP $HTTP_CODE (may need a moment)${NC}"
fi

echo ""
echo -e "${GREEN}=== Update complete! ===${NC}"
echo "Current version: $(git --no-pager log --oneline -1)"
