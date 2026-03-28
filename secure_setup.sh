#!/bin/bash

# GPS Tracker Security Hardening Script

echo "🛡️ GPS Tracker Security Setup"
echo "================================"

SERVER=${1:-"192.168.101.12"}
API_KEY=${2:-$(openssl rand -hex 32)}

echo "Target server: $SERVER"
echo "Generated API Key: $API_KEY"
echo ""

# Deploy secure application
echo "=== Step 1: Deploying Secure Application ==="
scp app_secure.py root@$SERVER:/tmp/
scp secure_setup.sh root@$SERVER:/tmp/

# Run security hardening on remote server
ssh root@$SERVER << EOF
set -e

echo "🔧 Creating dedicated GPS tracker user..."
# Create non-root user for GPS tracker
if ! id -u gps-tracker &>/dev/null; then
    useradd -r -s /bin/false -d /var/www/gps-tracker gps-tracker
    echo "✓ Created user: gps-tracker"
fi

echo "🔒 Setting up secure directories..."
# Create secure directory structure
mkdir -p /var/www/gps-tracker-secure
mkdir -p /var/log/gps-tracker
mkdir -p /etc/gps-tracker

# Copy secure application
cp /tmp/app_secure.py /var/www/gps-tracker-secure/app.py

# Set secure permissions
chown -R gps-tracker:gps-tracker /var/www/gps-tracker-secure
chown -R gps-tracker:gps-tracker /var/log/gps-tracker
chmod 755 /var/www/gps-tracker-secure
chmod 644 /var/www/gps-tracker-secure/app.py
chmod 600 /var/www/gps-tracker-secure/gps_tracker.db 2>/dev/null || true

echo "🌐 Setting up Python virtual environment..."
cd /var/www/gps-tracker-secure
python3 -m venv venv
source venv/bin/activate
pip install flask gunicorn

echo "🔐 Creating secure configuration..."
# Create environment file
cat > /etc/gps-tracker/config.env << EOL
GPS_API_KEY=$API_KEY
FLASK_ENV=production
PYTHONPATH=/var/www/gps-tracker-secure
EOL

chmod 600 /etc/gps-tracker/config.env
chown gps-tracker:gps-tracker /etc/gps-tracker/config.env

echo "🚫 Stopping old insecure service..."
systemctl stop gps-tracker 2>/dev/null || true
systemctl disable gps-tracker 2>/dev/null || true

echo "⚙️ Creating secure systemd service..."
cat > /etc/systemd/system/gps-tracker-secure.service << EOL
[Unit]
Description=Secure GPS Tracker Web Application  
After=network.target

[Service]
Type=notify
User=gps-tracker
Group=gps-tracker
WorkingDirectory=/var/www/gps-tracker-secure
Environment=PATH=/var/www/gps-tracker-secure/venv/bin
EnvironmentFile=/etc/gps-tracker/config.env
ExecStart=/var/www/gps-tracker-secure/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5001 --worker-class sync --timeout 30 --max-requests 1000 app:app
ExecReload=/bin/kill -s HUP \$MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=gps-tracker-secure

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/www/gps-tracker-secure
ReadWritePaths=/var/log/gps-tracker

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable gps-tracker-secure
systemctl start gps-tracker-secure

echo "🔥 Configuring firewall..."
# Configure UFW firewall
ufw --force enable
ufw default deny incoming  
ufw default allow outgoing
ufw allow 22    # SSH
ufw allow 80    # HTTP
ufw allow 443   # HTTPS
ufw delete allow 5000 2>/dev/null || true  # Remove old Flask port

echo "🌐 Setting up Nginx reverse proxy..."
# Install and configure Nginx
apt update
apt install -y nginx

# Create secure nginx configuration
cat > /etc/nginx/sites-available/gps-tracker-secure << EOL
server {
    listen 80;
    server_name _;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always; 
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline' unpkg.com; style-src 'self' 'unsafe-inline' unpkg.com; img-src 'self' data: *.openstreetmap.org; font-src 'self'" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=api:10m rate=10r/m;
    limit_req_zone \$binary_remote_addr zone=web:10m rate=60r/m;

    location / {
        limit_req zone=web burst=20 nodelay;
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 10s;
        proxy_read_timeout 10s;
    }

    location /api/ {
        limit_req zone=api burst=5 nodelay;
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # API-specific timeouts
        proxy_connect_timeout 3s;
        proxy_send_timeout 5s; 
        proxy_read_timeout 5s;
    }

    # Block common attack vectors
    location ~ /\.(ht|git|env) {
        deny all;
        return 404;
    }
    
    # Logging
    access_log /var/log/nginx/gps-tracker.access.log;
    error_log /var/log/nginx/gps-tracker.error.log;
}
EOL

# Enable site
ln -sf /etc/nginx/sites-available/gps-tracker-secure /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-enabled/gps-tracker

# Test and restart nginx
nginx -t && systemctl restart nginx
systemctl enable nginx

echo "✅ Security hardening complete!"
echo ""
echo "=== SECURE GPS TRACKER DEPLOYED ==="
echo "Web Interface: http://$SERVER/"
echo "API Endpoint: http://$SERVER/api/gps"
echo "API Key: $API_KEY"
echo ""
echo "Example API usage:"
echo "curl -X POST http://$SERVER/api/gps \\"
echo "  -H 'X-API-Key: $API_KEY' \\"
echo "  -H 'Content-Type: application/json' \\"
echo "  -d '{\"latitude\": 40.7128, \"longitude\": -74.0060, \"deviceId\": \"secure-device\"}'"
echo ""
echo "Service commands:"
echo "  systemctl status gps-tracker-secure"
echo "  systemctl restart gps-tracker-secure"
echo "  journalctl -u gps-tracker-secure -f"

EOF