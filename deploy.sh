#!/bin/bash

# GPS Tracker Deployment Script
# Usage: ./deploy.sh [username@]server_ip

SERVER=${1:-"192.168.101.12"}
REMOTE_DIR="/var/www/gps-tracker"
SERVICE_NAME="gps-tracker"

echo "=== GPS Tracker Deployment Script ==="
echo "Target server: $SERVER"
echo "Remote directory: $REMOTE_DIR"
echo ""

# Check if we can connect to the server
echo "Testing connection to $SERVER..."
if ! ping -c 1 $SERVER &> /dev/null; then
    echo "Error: Cannot reach server $SERVER"
    exit 1
fi

echo "Server is reachable!"

# Copy files to server
echo ""
echo "=== Step 1: Copying files to server ==="
echo "Creating remote directory..."
ssh $SERVER "sudo mkdir -p $REMOTE_DIR && sudo chown \$USER:\$USER $REMOTE_DIR"

echo "Copying application files..."
scp app.py requirements.txt README.md $SERVER:$REMOTE_DIR/

echo "Copying service file..."
scp gps-tracker.service $SERVER:/tmp/

# Install dependencies and setup
echo ""
echo "=== Step 2: Installing dependencies ==="
ssh $SERVER << 'ENDSSH'
    # Update system packages
    sudo apt update
    
    # Install Python and pip if not present
    sudo apt install -y python3 python3-pip python3-venv
    
    # Navigate to application directory
    cd /var/www/gps-tracker
    
    # Create virtual environment
    python3 -m venv venv
    
    # Activate virtual environment and install requirements
    source venv/bin/activate
    pip install -r requirements.txt
    
    # Test the application
    echo "Testing application..."
    python3 -c "import flask; print('Flask installed successfully')"
    
    # Set correct permissions
    sudo chown -R www-data:www-data /var/www/gps-tracker
    sudo chmod +x /var/www/gps-tracker/app.py
ENDSSH

# Setup systemd service
echo ""
echo "=== Step 3: Setting up systemd service ==="
ssh $SERVER << 'ENDSSH'
    # Copy service file to systemd directory
    sudo cp /tmp/gps-tracker.service /etc/systemd/system/
    
    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable gps-tracker
    
    # Start the service
    sudo systemctl start gps-tracker
    
    # Check service status
    sudo systemctl status gps-tracker --no-pager
ENDSSH

# Setup nginx (optional)
echo ""
echo "=== Step 4: Setting up Nginx reverse proxy (optional) ==="
read -p "Do you want to setup Nginx reverse proxy? (y/N): " setup_nginx

if [[ $setup_nginx =~ ^[Yy]$ ]]; then
    ssh $SERVER << 'ENDSSH'
        # Install nginx
        sudo apt install -y nginx
        
        # Create nginx configuration
        sudo tee /etc/nginx/sites-available/gps-tracker << 'EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF
        
        # Enable site and restart nginx
        sudo ln -sf /etc/nginx/sites-available/gps-tracker /etc/nginx/sites-enabled/
        sudo rm -f /etc/nginx/sites-enabled/default
        sudo systemctl restart nginx
        sudo systemctl enable nginx
ENDSSH
    echo "Nginx configured! GPS Tracker will be available on port 80"
else
    echo "Skipping Nginx setup. GPS Tracker will be available on port 5000"
fi

# Final status check
echo ""
echo "=== Step 5: Final status check ==="
ssh $SERVER << 'ENDSSH'
    echo "Service status:"
    sudo systemctl status gps-tracker --no-pager -l
    
    echo ""
    echo "Checking if application is responding:"
    sleep 2
    curl -s http://localhost:5000/api/health || echo "Application not responding yet - may need a moment to start"
    
    echo ""
    echo "Firewall status:"
    sudo ufw status || echo "UFW not active"
ENDSSH

echo ""
echo "=== Deployment Complete! ==="
echo ""
echo "GPS Tracker should now be running on:"
if [[ $setup_nginx =~ ^[Yy]$ ]]; then
    echo "  Web Interface: http://$SERVER/"
    echo "  API Endpoint:  http://$SERVER/api/gps"
else
    echo "  Web Interface: http://$SERVER:5000/"
    echo "  API Endpoint:  http://$SERVER:5000/api/gps"
fi
echo ""
echo "For Bareboat Necessities, configure GPS server to:"
echo "  URL: http://$SERVER/api/nmea (or :5000 if no nginx)"
echo "  Method: POST"
echo "  Format: NMEA sentences"
echo ""
echo "Useful commands on the server:"
echo "  sudo systemctl status gps-tracker    # Check service status"
echo "  sudo systemctl restart gps-tracker   # Restart service"
echo "  sudo journalctl -u gps-tracker -f    # View logs"
echo "  tail -f /var/www/gps-tracker/gps_tracker.db  # Check database"