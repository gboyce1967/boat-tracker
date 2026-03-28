# 🛡️ Secure GPS Tracker with Authentication

A robust, production-ready GPS tracking web application with user authentication, admin management, and secure API endpoints for maritime navigation systems.

## ✨ Features

### 🔐 Security & Authentication
- **User Authentication System** - Secure login/logout with session management
- **Role-Based Access Control** - Admin and regular user privileges
- **Password Hashing** - Werkzeug secure password storage
- **API Key Authentication** - Secure GPS data submission
- **Rate Limiting** - Protection against abuse
- **Input Validation** - Sanitization and validation of all inputs

### 👥 User Management
- **Admin Dashboard** - Create, view, and delete users
- **User Roles** - Administrator and regular user permissions
- **Account Management** - Email, password, and role configuration
- **Login History** - Track user access patterns

### 🗺️ GPS Tracking
- **Real-time Mapping** - Interactive OpenStreetMap integration
- **Persistent Map View** - Map position and zoom preserved across refreshes
- **Multiple Data Formats** - JSON and NMEA sentence support
- **Device Tracking** - Support for multiple GPS devices
- **Data Visualization** - Statistics and coordinate history
- **Auto-refresh** - Real-time updates every 60 seconds without losing your view

### 🌤️ Weather & Radar
- **Live Weather Data** - Temperature (°F), humidity, pressure (inHg), wind speed (mph), visibility (mi)
- **Weather Radar** - Real-time precipitation radar overlay using RainViewer API
- **Imperial Units** - All weather data displayed in US customary units
- **Auto-updates** - Weather data updates every 15 minutes automatically
- **Manual Refresh** - Refresh button to update weather on-demand
- **Location-based** - Weather is fetched for your latest GPS coordinates
- **OpenWeatherMap Integration** - Professional weather data API

### ⛵ Boat Information Management
- **Boat Specifications** - Store and display detailed boat information
- **Boat Image Upload** - Upload and display boat photos (JPG, PNG, GIF, WEBP)
- **Comprehensive Details** - Registration number, BIN, model, year, color, dimensions
- **Physical Specifications** - Length, draft, beam measurements in feet
- **Engine Information** - Engine size (hp), serial number tracking
- **Fuel System** - Fuel tank capacity in gallons
- **Admin Management** - Admins can edit boat info through Settings page
- **Public Display** - All users can view boat information
- **Custom Fields** - Extensible JSON storage for additional boat attributes

### 🗺️ Float Plan Management
- **Trip Planning** - Create detailed float plans with multiple legs/waypoints
- **GPS Coordinates** - Store waypoint locations in decimal degrees format
- **Comprehensive Details** - Location names, addresses, arrival/departure times
- **Contact Information** - Phone numbers and VHF channels for each location
- **Navigation Data** - Speed estimates, fuel consumption, travel duration
- **Approach Instructions** - Detailed navigation notes for each waypoint
- **Location Types** - Categorize as departure, waypoint, or destination
- **Edit & Update** - Full edit capability to modify existing float plans
- **Reset Function** - Clear entire float plan to start fresh
- **User Access** - All logged-in users can view and manage float plans

### 🛡️ Production Security
- **HTTPS Encryption** - SSL/TLS with security headers
- **Content Security Policy** - Protection against XSS attacks
- **Secure Headers** - HSTS, frame options, content type protection
- **Input Sanitization** - Protection against injection attacks

## 🚀 Quick Installation

### Prerequisites
- Ubuntu/Debian Linux server
- Root access
- Domain name (DNS configured)

### One-Command Installation
```bash
sudo bash install.sh
```

The installation script will:
1. Install system dependencies (Python, Nginx, SQLite)
2. Create service user and directories
3. Set up Python virtual environment
4. Initialize SQLite database with admin user
5. Configure systemd service
6. Generate SSL certificates
7. Configure Nginx with security headers
8. Start all services

## 📋 Manual Installation

### 1. System Dependencies
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv sqlite3 nginx openssl
```

### 2. Create Service User
```bash
sudo useradd --system --shell /bin/bash --home-dir /var/www/gps-tracker-secure --create-home gps-tracker
```

### 3. Setup Application
```bash
sudo mkdir -p /var/www/gps-tracker-secure
cd /var/www/gps-tracker-secure

# Copy application files
sudo cp app.py init_db.py requirements.txt /var/www/gps-tracker-secure/

# Create virtual environment
sudo -u gps-tracker python3 -m venv venv
sudo -u gps-tracker venv/bin/pip install -r requirements.txt

# Initialize database
sudo -u gps-tracker venv/bin/python init_db.py
```

### 4. Configure Systemd Service
```bash
sudo cp gps-tracker-secure.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable gps-tracker-secure
sudo systemctl start gps-tracker-secure
```

### 5. Setup SSL Certificate
```bash
# Generate self-signed certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/private/boat-tracker.grayworkscrafts.com.key \
    -out /etc/ssl/certs/boat-tracker.grayworkscrafts.com.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=boat-tracker.grayworkscrafts.com"

# Generate DH parameters
sudo openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
```

### 6. Configure Nginx
```bash
sudo cp nginx-gps-tracker.conf /etc/nginx/sites-available/gps-tracker
sudo ln -s /etc/nginx/sites-available/gps-tracker /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 7. Set Permissions
```bash
sudo chown -R gps-tracker:gps-tracker /var/www/gps-tracker-secure
sudo chmod 755 /var/www/gps-tracker-secure
```

### 8. Configure Weather Feature (Optional)
```bash
# Get a free API key from https://openweathermap.org/api
# Add to configuration file:
sudo nano /etc/gps-tracker/config.env

# Add this line:
OPENWEATHER_API_KEY=your_api_key_here

# Restart service
sudo systemctl restart gps-tracker-secure
```

## 🔧 Configuration

### Environment Variables
Set in `/etc/gps-tracker/config.env`:
- `GPS_API_KEY` - API key for GPS data submission (auto-generated)
- `FLASK_SECRET_KEY` - Persistent secret key for Flask sessions (auto-generated)
- `OPENWEATHER_API_KEY` - OpenWeatherMap API key for weather data (optional)
- `FLASK_ENV` - Production environment setting

### Database Location
- SQLite database: `/var/www/gps-tracker-secure/gps_tracker.db`

### Log Files
- Application logs: `journalctl -u gps-tracker-secure -f`
- Nginx logs: `/var/log/nginx/access.log` and `/var/log/nginx/error.log`
- Weather updates: `/var/log/weather-update.log`

## 📡 API Endpoints

### GPS Data Submission
```bash
# JSON Format
curl -X POST https://your-domain.com/api/gps \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"latitude": 40.7128, "longitude": -74.0060, "deviceId": "boat-01"}'

# NMEA Format
curl -X POST https://your-domain.com/api/nmea \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: text/plain" \
  -d '$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47'
```

### Health Check
```bash
curl https://your-domain.com/api/health
```

Response:
```json
{
  "status": "healthy",
  "pointsStored": 150,
  "uniqueDevices": 3,
  "serverTime": "2024-01-15T10:30:00",
  "securityMode": "enabled",
  "authenticationEnabled": true
}
```

## 👤 Default Admin Account

**First-time setup creates a default admin account:**
- Username: `admin`
- Password: `[randomly generated - check installation output]`

**⚠️ Change this password immediately after first login!**

## 🛠️ Management Commands

### Service Management
```bash
# Restart application
sudo systemctl restart gps-tracker-secure

# View logs
sudo journalctl -u gps-tracker-secure -f

# Check status
sudo systemctl status gps-tracker-secure

# Stop service
sudo systemctl stop gps-tracker-secure

# Start service
sudo systemctl start gps-tracker-secure
```

**Note:** The systemd service is configured with `KillMode=control-group` to ensure all gunicorn worker processes are properly terminated on restart, preventing port conflicts.

### Database Management
```bash
# Access database
sudo -u gps-tracker sqlite3 /var/www/gps-tracker-secure/gps_tracker.db

# Reset admin password
cd /var/www/gps-tracker-secure
sudo -u gps-tracker venv/bin/python init_db.py
```

### Nginx Management
```bash
# Reload configuration
sudo systemctl reload nginx

# Test configuration
sudo nginx -t

# View logs
sudo tail -f /var/log/nginx/access.log
```

## 🔒 Security Considerations

### SSL/TLS Configuration
- **Self-signed certificates** are generated by default
- **Production deployment** should use Let's Encrypt or commercial certificates
- **Strong ciphers** and modern TLS protocols configured

### Network Security
- **Rate limiting** prevents API abuse
- **Security headers** protect against common attacks
- **HTTPS redirect** enforces encrypted connections

### Application Security
- **Password hashing** using Werkzeug secure methods
- **Session management** with secure cookies
- **Input validation** prevents injection attacks
- **API authentication** required for data submission

### Recommended Additional Security
1. **Firewall configuration** (UFW or iptables)
2. **Fail2ban** for brute-force protection
3. **Regular security updates**
4. **Log monitoring and alerting**
5. **Backup strategy for database**

## 📊 User Interface

### Login Page
- Secure authentication form
- Error handling and validation
- First-time setup guidance

### Dashboard
- Real-time GPS tracking map
- Persistent map view (position and zoom preserved across refreshes)
- Manual re-center button to jump to latest GPS coordinate
- Statistics and metrics
- Recent coordinates display
- Auto-refresh functionality that respects your map position

### Admin Panel
- User management interface
- Create/delete user accounts
- Password reset for any user
- Role assignment (admin/user)
- User activity monitoring

### Password Management
- Change your own password via Settings
- Admin password reset for other users
- Secure password validation
- Automatic password generation for resets

### Boat Information Page
- View boat specifications and details
- Display boat photo/image
- Registration and identification numbers
- Physical dimensions and engine specifications
- Admin edit access through Settings

### Float Plan Page
- Create multi-leg trip plans with detailed waypoints
- Add/edit/remove legs dynamically
- Enter GPS coordinates in decimal degree format
- Store arrival and departure times for each location
- Include marina/facility contact information
- Add approach instructions and navigation notes
- Track fuel consumption and speed estimates
- Reset entire float plan when starting new trip
- Access from main navigation menu

### Weather & Radar Page
- Real-time weather conditions
- Interactive radar map with precipitation overlay
- Auto-refresh every 15 minutes
- Manual refresh button

## 🔄 Updating the Application

1. **Stop the service**
   ```bash
   sudo systemctl stop gps-tracker
   ```

2. **Backup database**
   ```bash
   sudo cp /var/www/gps-tracker/gps_tracker.db /backup/
   ```

3. **Update application files**
   ```bash
   sudo cp app.py /var/www/gps-tracker/
   sudo chown gps-tracker:gps-tracker /var/www/gps-tracker/app.py
   ```

4. **Restart service**
   ```bash
   sudo systemctl start gps-tracker
   ```

## 🐛 Troubleshooting

### Service Won't Start
```bash
# Check service status
sudo systemctl status gps-tracker

# View detailed logs
sudo journalctl -u gps-tracker --no-pager

# Check file permissions
ls -la /var/www/gps-tracker/
```

### SSL Certificate Issues
```bash
# Verify certificate
openssl x509 -in /etc/ssl/certs/boat-tracker.grayworkscrafts.com.crt -text -noout

# Check certificate permissions
ls -la /etc/ssl/private/ /etc/ssl/certs/
```

### Database Issues
```bash
# Check database file
sudo -u gps-tracker file /var/www/gps-tracker/gps_tracker.db

# Verify database structure
sudo -u gps-tracker sqlite3 /var/www/gps-tracker/gps_tracker.db ".schema"
```

### Nginx Configuration Issues
```bash
# Test configuration
sudo nginx -t

# Check site configuration
sudo nginx -T | grep -A 20 boat-tracker
```

### Session/Login Issues (Getting Logged Out)
```bash
# Check if Flask secret key is persistent
sudo grep FLASK_SECRET_KEY /etc/systemd/system/gps-tracker.service

# If missing, add persistent secret key
FLASK_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
sudo sed -i "/Environment=GPS_API_KEY/a Environment=FLASK_SECRET_KEY=$FLASK_SECRET" /etc/systemd/system/gps-tracker.service

# Restart service
sudo systemctl daemon-reload
sudo systemctl restart gps-tracker
```

### Password Management Issues
```bash
# Reset admin password manually
cd /var/www/gps-tracker
sudo -u gps-tracker venv/bin/python init_db.py

# Check user passwords in database
sudo -u gps-tracker sqlite3 gps_tracker.db "SELECT username, created_at, last_login FROM users;"
```

## 📝 License

This GPS Tracker application is provided as-is for educational and personal use. Ensure compliance with local maritime and privacy regulations when deploying in production environments.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section above
2. Review service logs: `sudo journalctl -u gps-tracker -f`
3. Verify system resources and permissions
4. Ensure all dependencies are properly installed

---

**🛡️ Your secure GPS tracking system is ready for maritime adventures!**