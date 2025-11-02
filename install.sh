#!/bin/bash
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

clear
echo -e "${BLUE}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║         🛡️  GPS Tracker Interactive Installer  ⛵            ║
║                                                               ║
║     Secure GPS tracking with authentication & float plans    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}❌ This script must be run as root (use sudo)${NC}"
   exit 1
fi

# Check OS
if [ ! -f /etc/os-release ]; then
    echo -e "${RED}❌ Cannot detect OS. This installer supports Ubuntu/Debian only.${NC}"
    exit 1
fi

source /etc/os-release
if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
    echo -e "${YELLOW}⚠️  Warning: This installer is designed for Ubuntu/Debian.${NC}"
    echo -e "   Detected OS: $PRETTY_NAME"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                    CONFIGURATION${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Function to validate domain
validate_domain() {
    local domain=$1
    if [[ $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 0
    else
        return 1
    fi
}

# Function to validate port
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1024 ] && [ $port -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# Domain Name
echo -e "${YELLOW}📍 Domain Configuration${NC}"
echo "   Enter the domain name where this GPS tracker will be accessible."
echo "   Examples: tracker.example.com, gps.myboat.net"
echo ""
while true; do
    read -p "   Domain name: " DOMAIN
    if [ -z "$DOMAIN" ]; then
        echo -e "${RED}   ❌ Domain name cannot be empty${NC}"
        continue
    fi
    if validate_domain "$DOMAIN"; then
        break
    else
        echo -e "${RED}   ❌ Invalid domain format. Please try again.${NC}"
    fi
done
echo ""

# Port Configuration
echo -e "${YELLOW}🔌 Port Configuration${NC}"
echo "   The application will run on this port (proxied by Nginx)."
echo "   Default: 5001 (recommended)"
echo ""
while true; do
    read -p "   Application port [5001]: " APP_PORT
    APP_PORT=${APP_PORT:-5001}
    if validate_port "$APP_PORT"; then
        break
    else
        echo -e "${RED}   ❌ Invalid port. Must be between 1024-65535.${NC}"
    fi
done
echo ""

# Check if port is in use
if lsof -Pi :$APP_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${RED}   ⚠️  Warning: Port $APP_PORT is already in use!${NC}"
    read -p "   Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Installation Directory
echo -e "${YELLOW}📁 Installation Directory${NC}"
echo "   Where should the application be installed?"
echo "   Default: /var/www/gps-tracker-secure"
echo ""
read -p "   Installation path [/var/www/gps-tracker-secure]: " APP_DIR
APP_DIR=${APP_DIR:-/var/www/gps-tracker-secure}
echo ""

# Service User
SERVICE_USER="gps-tracker"
APP_NAME="gps-tracker-secure"

# SSL Certificate Options
echo -e "${YELLOW}🔐 SSL Certificate Configuration${NC}"
echo "   Choose how to configure HTTPS for your domain:"
echo ""
echo "   1) Self-signed certificate (for testing/development)"
echo "   2) Let's Encrypt certificate (recommended for production)"
echo "   3) I will provide my own certificate files"
echo ""
while true; do
    read -p "   Select option [2]: " SSL_CHOICE
    SSL_CHOICE=${SSL_CHOICE:-2}
    if [[ "$SSL_CHOICE" =~ ^[1-3]$ ]]; then
        break
    else
        echo -e "${RED}   ❌ Invalid choice. Enter 1, 2, or 3.${NC}"
    fi
done
echo ""

# Let's Encrypt email if option 2 selected
if [ "$SSL_CHOICE" = "2" ]; then
    echo -e "${YELLOW}📧 Let's Encrypt Configuration${NC}"
    echo "   Enter an email address for Let's Encrypt notifications."
    echo ""
    while true; do
        read -p "   Email address: " LETSENCRYPT_EMAIL
        if [[ $LETSENCRYPT_EMAIL =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            break
        else
            echo -e "${RED}   ❌ Invalid email format${NC}"
        fi
    done
    echo ""
fi

# Weather API Key (optional)
echo -e "${YELLOW}🌤️  Weather Integration (Optional)${NC}"
echo "   Enter your OpenWeatherMap API key to enable weather features."
echo "   Get a free key at: https://openweathermap.org/api"
echo "   Leave blank to skip."
echo ""
read -p "   API Key (optional): " WEATHER_API_KEY
echo ""

# Generate API key for GPS data submission
API_KEY=$(openssl rand -hex 32)

# Configuration Summary
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}              CONFIGURATION SUMMARY${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}Domain:${NC}            $DOMAIN"
echo -e "${GREEN}Application Port:${NC}  $APP_PORT"
echo -e "${GREEN}Install Directory:${NC} $APP_DIR"
echo -e "${GREEN}Service User:${NC}      $SERVICE_USER"
echo -e "${GREEN}Service Name:${NC}      $APP_NAME"
if [ "$SSL_CHOICE" = "1" ]; then
    echo -e "${GREEN}SSL Certificate:${NC}   Self-signed"
elif [ "$SSL_CHOICE" = "2" ]; then
    echo -e "${GREEN}SSL Certificate:${NC}   Let's Encrypt ($LETSENCRYPT_EMAIL)"
else
    echo -e "${GREEN}SSL Certificate:${NC}   User-provided"
fi
if [ -n "$WEATHER_API_KEY" ]; then
    echo -e "${GREEN}Weather API:${NC}       Configured"
else
    echo -e "${GREEN}Weather API:${NC}       Disabled"
fi
echo -e "${GREEN}GPS API Key:${NC}       ${API_KEY:0:16}... (will be generated)"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

read -p "Continue with installation? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}❌ Installation cancelled${NC}"
    exit 1
fi

echo ""
echo -e "${BLUE}🚀 Starting installation...${NC}"
echo ""

# Pre-flight checks
echo -e "${BLUE}🔍 Running pre-flight checks...${NC}"

# Check internet connectivity
if ! ping -c 1 8.8.8.8 >/dev/null 2>&1; then
    echo -e "${RED}   ❌ No internet connection detected${NC}"
    exit 1
fi
echo "   ✅ Internet connection OK"

# Check available disk space (at least 500MB)
AVAILABLE_SPACE=$(df / | tail -1 | awk '{print $4}')
if [ "$AVAILABLE_SPACE" -lt 500000 ]; then
    echo -e "${YELLOW}   ⚠️  Warning: Low disk space (less than 500MB available)${NC}"
fi
echo "   ✅ Disk space OK"

# Check if directory already exists
if [ -d "$APP_DIR" ]; then
    echo -e "${YELLOW}   ⚠️  Warning: Installation directory already exists${NC}"
    read -p "   Overwrite existing installation? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}   ❌ Installation cancelled${NC}"
        exit 1
    fi
fi
echo "   ✅ Pre-flight checks complete"
echo ""

# Install system dependencies
echo -e "${BLUE}📦 Installing system dependencies...${NC}"
apt update -qq
apt install -y -qq python3 python3-pip python3-venv sqlite3 nginx openssl lsof >/dev/null 2>&1
echo "   ✅ System dependencies installed"
echo ""

# Install certbot if Let's Encrypt selected
if [ "$SSL_CHOICE" = "2" ]; then
    echo -e "${BLUE}📦 Installing certbot for Let's Encrypt...${NC}"
    apt install -y -qq certbot python3-certbot-nginx >/dev/null 2>&1
    echo "   ✅ Certbot installed"
    echo ""
fi

# Create service user
echo -e "${BLUE}👤 Creating service user...${NC}"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd --system --shell /bin/bash --home-dir "$APP_DIR" --create-home "$SERVICE_USER"
    echo "   ✅ User $SERVICE_USER created"
else
    echo "   ℹ️  User $SERVICE_USER already exists"
fi
echo ""

# Setup application directory
echo -e "${BLUE}📁 Setting up application directory...${NC}"
mkdir -p "$APP_DIR"
cd "$APP_DIR"

# Copy application files from the same directory as the installer
INSTALLER_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$INSTALLER_DIR/app.py" ]; then
    cp "$INSTALLER_DIR/app.py" "$APP_DIR/"
    echo "   ✅ Copied app.py"
else
    echo -e "${RED}   ❌ app.py not found in installer directory${NC}"
    exit 1
fi

if [ -f "$INSTALLER_DIR/requirements.txt" ]; then
    cp "$INSTALLER_DIR/requirements.txt" "$APP_DIR/"
    echo "   ✅ Copied requirements.txt"
else
    echo -e "${RED}   ❌ requirements.txt not found in installer directory${NC}"
    exit 1
fi

if [ -f "$INSTALLER_DIR/init_db.py" ]; then
    cp "$INSTALLER_DIR/init_db.py" "$APP_DIR/"
    echo "   ✅ Copied init_db.py"
else
    echo -e "${YELLOW}   ⚠️  init_db.py not found (will use app.py init)${NC}"
fi
echo ""

# Create Python virtual environment
echo -e "${BLUE}🐍 Creating Python virtual environment...${NC}"
python3 -m venv venv
source venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt
echo "   ✅ Virtual environment created and dependencies installed"
echo ""

# Initialize database
echo -e "${BLUE}🗄️  Initializing database...${NC}"
if [ -f "$APP_DIR/init_db.py" ]; then
    INIT_OUTPUT=$(./venv/bin/python init_db.py 2>&1)
    echo "$INIT_OUTPUT" | grep -E "(created|Password)" || true
    ADMIN_PASSWORD=$(echo "$INIT_OUTPUT" | grep "Password:" | awk '{print $3}' | tail -1)
else
    # Database will be initialized on first run
    echo "   ℹ️  Database will be initialized on first application start"
fi
echo "   ✅ Database ready"
echo ""

# Create directories
echo -e "${BLUE}📁 Creating application directories...${NC}"
mkdir -p "$APP_DIR/static/boat_images"
mkdir -p /var/log/gps-tracker
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/static/boat_images"
chown -R "$SERVICE_USER:$SERVICE_USER" /var/log/gps-tracker
chmod 775 "$APP_DIR/static/boat_images"
echo "   ✅ Directories created"
echo ""

# Setup systemd service
echo -e "${BLUE}🔧 Configuring systemd service...${NC}"
FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")

# Create config directory
mkdir -p /etc/gps-tracker
cat > /etc/gps-tracker/config.env << EOF
GPS_API_KEY=$API_KEY
FLASK_SECRET_KEY=$FLASK_SECRET
OPENWEATHER_API_KEY=$WEATHER_API_KEY
FLASK_ENV=production
EOF

chmod 600 /etc/gps-tracker/config.env

# Create systemd service file
cat > /etc/systemd/system/$APP_NAME.service << EOF
[Unit]
Description=Secure GPS Tracker Web Application
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
Environment=PATH=$APP_DIR/venv/bin
EnvironmentFile=/etc/gps-tracker/config.env
ExecStart=$APP_DIR/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:$APP_PORT --worker-class sync --timeout 30 --max-requests 1000 --pid /tmp/gps-tracker-gunicorn.pid app:app
ExecReload=/bin/kill -s HUP \$MAINPID
KillMode=control-group
KillSignal=SIGTERM
TimeoutStopSec=30
SendSIGKILL=yes
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$APP_NAME

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$APP_DIR
ReadWritePaths=/var/log/gps-tracker
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
EOF

echo "   ✅ Systemd service configured"
echo ""

# SSL Certificate Setup
echo -e "${BLUE}🔐 Setting up SSL certificates...${NC}"
mkdir -p /etc/ssl/private /etc/ssl/certs

if [ "$SSL_CHOICE" = "1" ]; then
    # Self-signed certificate
    if [ ! -f "/etc/ssl/certs/$DOMAIN.crt" ]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "/etc/ssl/private/$DOMAIN.key" \
            -out "/etc/ssl/certs/$DOMAIN.crt" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" \
            >/dev/null 2>&1
        
        if [ ! -f "/etc/ssl/certs/dhparam.pem" ]; then
            openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048 >/dev/null 2>&1
        fi
        
        echo "   ✅ Self-signed certificate generated"
    else
        echo "   ℹ️  Certificate already exists"
    fi
    CERT_PATH="/etc/ssl/certs/$DOMAIN.crt"
    KEY_PATH="/etc/ssl/private/$DOMAIN.key"
    
elif [ "$SSL_CHOICE" = "2" ]; then
    # Let's Encrypt
    echo "   🔄 Obtaining Let's Encrypt certificate..."
    echo "      This may take a minute..."
    
    # Temporarily configure nginx for certbot
    cat > /etc/nginx/sites-available/temp-certbot << EOF
server {
    listen 80;
    server_name $DOMAIN;
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}
EOF
    
    ln -sf /etc/nginx/sites-available/temp-certbot /etc/nginx/sites-enabled/
    systemctl reload nginx 2>/dev/null || true
    
    # Run certbot
    certbot certonly --nginx -d $DOMAIN --non-interactive --agree-tos --email $LETSENCRYPT_EMAIL --quiet
    
    if [ $? -eq 0 ]; then
        echo "   ✅ Let's Encrypt certificate obtained"
        CERT_PATH="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        KEY_PATH="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    else
        echo -e "${RED}   ❌ Failed to obtain Let's Encrypt certificate${NC}"
        echo "      Falling back to self-signed certificate..."
        SSL_CHOICE=1
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout "/etc/ssl/private/$DOMAIN.key" \
            -out "/etc/ssl/certs/$DOMAIN.crt" \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=$DOMAIN" \
            >/dev/null 2>&1
        CERT_PATH="/etc/ssl/certs/$DOMAIN.crt"
        KEY_PATH="/etc/ssl/private/$DOMAIN.key"
    fi
    
    rm -f /etc/nginx/sites-enabled/temp-certbot
    
else
    # User-provided certificates
    echo "   ℹ️  Please place your certificate files:"
    echo "      Certificate: /etc/ssl/certs/$DOMAIN.crt"
    echo "      Private Key: /etc/ssl/private/$DOMAIN.key"
    echo ""
    read -p "   Press Enter when certificates are in place..."
    
    if [ ! -f "/etc/ssl/certs/$DOMAIN.crt" ] || [ ! -f "/etc/ssl/private/$DOMAIN.key" ]; then
        echo -e "${RED}   ❌ Certificate files not found${NC}"
        exit 1
    fi
    CERT_PATH="/etc/ssl/certs/$DOMAIN.crt"
    KEY_PATH="/etc/ssl/private/$DOMAIN.key"
    echo "   ✅ User-provided certificates found"
fi
echo ""

# Configure Nginx
echo -e "${BLUE}🌐 Configuring Nginx...${NC}"
cat > /etc/nginx/sites-available/$APP_NAME << EOF
# HTTP - Redirect to HTTPS
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

# HTTPS
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $DOMAIN;

    # SSL Configuration
    ssl_certificate $CERT_PATH;
    ssl_certificate_key $KEY_PATH;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Logging
    access_log /var/log/nginx/gps-tracker-access.log;
    error_log /var/log/nginx/gps-tracker-error.log;

    # Client body size (for image uploads)
    client_max_body_size 10M;

    # Proxy to application
    location / {
        proxy_pass http://127.0.0.1:$APP_PORT;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_redirect off;
        
        # WebSocket support (if needed in future)
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Static files (if served directly)
    location /static/ {
        alias $APP_DIR/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/$APP_NAME /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true

# Test nginx configuration
if nginx -t >/dev/null 2>&1; then
    echo "   ✅ Nginx configuration OK"
else
    echo -e "${RED}   ❌ Nginx configuration test failed${NC}"
    nginx -t
    exit 1
fi
echo ""

# Set permissions
echo -e "${BLUE}🔒 Setting permissions...${NC}"
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"
chmod 755 "$APP_DIR"
if [ "$SSL_CHOICE" != "2" ]; then
    # For Let's Encrypt, certbot manages permissions
    chmod 600 "$KEY_PATH" 2>/dev/null || true
    chmod 644 "$CERT_PATH" 2>/dev/null || true
fi
echo "   ✅ Permissions set"
echo ""

# Start services
echo -e "${BLUE}🚀 Starting services...${NC}"
systemctl daemon-reload
systemctl enable $APP_NAME >/dev/null 2>&1
systemctl start $APP_NAME
systemctl reload nginx

# Wait for service to start
sleep 3

# Verify service is running
if systemctl is-active --quiet $APP_NAME; then
    echo "   ✅ $APP_NAME is running"
else
    echo -e "${RED}   ❌ $APP_NAME failed to start${NC}"
    echo "      Check logs: journalctl -u $APP_NAME --no-pager"
    exit 1
fi

if systemctl is-active --quiet nginx; then
    echo "   ✅ Nginx is running"
else
    echo -e "${RED}   ❌ Nginx failed to start${NC}"
    systemctl status nginx --no-pager
    exit 1
fi
echo ""

# Save installation details
INSTALL_LOG="$APP_DIR/installation_details.txt"
cat > "$INSTALL_LOG" << EOF
GPS Tracker Installation Details
=================================
Installation Date: $(date)
Domain: $DOMAIN
Application Port: $APP_PORT
Installation Directory: $APP_DIR
Service Name: $APP_NAME
Service User: $SERVICE_USER

SSL Certificate: $([[ "$SSL_CHOICE" == "1" ]] && echo "Self-signed" || [[ "$SSL_CHOICE" == "2" ]] && echo "Let's Encrypt" || echo "User-provided")
Weather API: $([[ -n "$WEATHER_API_KEY" ]] && echo "Configured" || echo "Not configured")

Admin Credentials:
  Username: admin
  Password: ${ADMIN_PASSWORD:-Check logs with: journalctl -u $APP_NAME | grep Password}

API Configuration:
  GPS API Key: $API_KEY
  GPS Endpoint: https://$DOMAIN/api/gps
  Health Check: https://$DOMAIN/api/health

Management Commands:
  Restart service: systemctl restart $APP_NAME
  View logs: journalctl -u $APP_NAME -f
  Reload nginx: systemctl reload nginx
  Check status: systemctl status $APP_NAME

Configuration Files:
  Service: /etc/systemd/system/$APP_NAME.service
  Environment: /etc/gps-tracker/config.env
  Nginx: /etc/nginx/sites-available/$APP_NAME
  Database: $APP_DIR/gps_tracker.db

Support:
  Documentation: $APP_DIR/README.md
  Float Plan Guide: $APP_DIR/FLOAT_PLAN_GUIDE.md
EOF

chmod 600 "$INSTALL_LOG"
chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_LOG"

# Installation complete!
clear
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║            ✅  Installation Complete!  🎉                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"
echo ""

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}              YOUR GPS TRACKER IS READY!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}📍 Access your GPS Tracker:${NC}"
echo "   URL: https://$DOMAIN"
echo ""
echo -e "${GREEN}🔐 Default Admin Credentials:${NC}"
echo "   Username: admin"
if [ -n "$ADMIN_PASSWORD" ]; then
    echo "   Password: $ADMIN_PASSWORD"
else
    echo "   Password: Check logs with: journalctl -u $APP_NAME | grep Password"
fi
echo ""
echo -e "${YELLOW}⚠️  IMPORTANT: Change the admin password after first login!${NC}"
echo ""
echo -e "${GREEN}📊 API Configuration:${NC}"
echo "   API Key: $API_KEY"
echo "   GPS Endpoint: https://$DOMAIN/api/gps"
echo "   Health Check: https://$DOMAIN/api/health"
echo ""
echo -e "${GREEN}🛠️  Management Commands:${NC}"
echo "   Restart service:  systemctl restart $APP_NAME"
echo "   View logs:        journalctl -u $APP_NAME -f"
echo "   Check status:     systemctl status $APP_NAME"
echo "   Reload nginx:     systemctl reload nginx"
echo ""
echo -e "${GREEN}📁 Installation Details:${NC}"
echo "   Saved to: $INSTALL_LOG"
echo ""

if [ "$SSL_CHOICE" = "1" ]; then
    echo -e "${YELLOW}🔐 SSL Certificate Note:${NC}"
    echo "   You are using a self-signed certificate."
    echo "   For production, consider obtaining a trusted certificate with:"
    echo "   certbot --nginx -d $DOMAIN"
    echo ""
fi

if [ -z "$WEATHER_API_KEY" ]; then
    echo -e "${YELLOW}🌤️  Weather Feature:${NC}"
    echo "   Weather features are disabled."
    echo "   To enable, add an OpenWeatherMap API key:"
    echo "   1. Get free key: https://openweathermap.org/api"
    echo "   2. Edit: /etc/gps-tracker/config.env"
    echo "   3. Restart: systemctl restart $APP_NAME"
    echo ""
fi

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}✅ Your secure GPS tracker is ready for maritime adventures!${NC}"
echo ""
