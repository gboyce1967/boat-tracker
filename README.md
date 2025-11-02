# 🛡️ GPS Tracker - Interactive Installer

A complete, production-ready GPS tracking web application with user authentication, float plans, weather integration, and secure API endpoints designed for maritime navigation.

## 📖 Background

I built this using the **Warp AI terminal**. I needed a way for my family to be able to keep track of me when underway. We use [Bareboat Necessities](https://bareboat-necessities.github.io/) running on a Raspberry Pi 5 on the boat and use SignalK to transmit the GPS data back to the boat-tracker. 

It started out as just a tracker and I realized pretty quickly that some other features would be useful. So, I added:

- 🌤️ **Weather and radar** that updates based on GPS location every 15 minutes
- ⛵ **Boat information page** with vessel specs and photos
- 🗺️ **Track management** - ability to lay tracks where I've been
- 📍 **Waypoint and route uploads** for navigation planning
- 📋 **Float plan page** for detailed trip planning

Now my wife is very happy and feeling much more secure while I'm away. I hope this helps you as well!

## ✨ Features

- **🔐 Secure Authentication** - User management with role-based access
- **🗺️ Real-time GPS Tracking** - Interactive map with live position updates
- **⛵ Float Plan Management** - Plan multi-leg trips with detailed waypoints
- **🌤️ Weather Integration** - Live weather and radar data (OpenWeatherMap)
- **📍 Boat Information** - Store vessel specifications and photos
- **🔒 Production Security** - SSL/TLS, security headers, input validation
- **📡 API Endpoints** - Secure GPS data submission with API key auth
- **👥 User Management** - Admin dashboard for user accounts

## 🚀 Quick Start

### Requirements

- **OS**: Ubuntu 20.04+ or Debian 11+ (64-bit)
- **Access**: Root/sudo privileges
- **Resources**: 1GB RAM minimum, 2GB disk space
- **Network**: Internet connection for installation
- **Domain**: A domain name pointing to your server (for Let's Encrypt)

### Installation

1. **Download the installer package**
   ```bash
   # Extract the installer files to a directory
   cd boat-tracker_installer
   ```

2. **Run the interactive installer**
   ```bash
   sudo bash install.sh
   ```

3. **Follow the prompts**
   - Enter your domain name
   - Choose application port (default: 5001)
   - Select SSL certificate option
   - Optionally enter weather API key
   - Review configuration and confirm

4. **Access your GPS Tracker**
   - Visit `https://your-domain.com`
   - Login with the admin credentials shown

That's it! The installer handles everything automatically.

## 📋 What Gets Installed

The installer will:

✅ Install system dependencies (Python, Nginx, SQLite, SSL tools)  
✅ Create a dedicated service user (`gps-tracker`)  
✅ Set up Python virtual environment with all dependencies  
✅ Initialize the database with admin user  
✅ Configure systemd service with proper process management  
✅ Generate or obtain SSL certificates (self-signed or Let's Encrypt)  
✅ Configure Nginx as reverse proxy with security headers  
✅ Create all necessary directories with correct permissions  
✅ Start and enable all services  

## 🔐 SSL Certificate Options

### Option 1: Self-Signed Certificate (Development/Testing)
- Generated automatically during installation
- Works immediately but browsers will show security warning
- Perfect for testing and internal use
- Can upgrade to Let's Encrypt later

### Option 2: Let's Encrypt (Production - Recommended)
- Free, trusted SSL certificate
- Automatically obtained and configured
- Requires: Domain pointing to server + port 80 accessible
- Auto-renewal configured
- Best for production deployments

### Option 3: Provide Your Own Certificate
- Use your own SSL certificate files
- Place files before installation or when prompted
- Supports commercial certificates

## 🌤️ Weather Integration (Optional)

The GPS Tracker can display real-time weather and radar:

1. Get a free API key from [OpenWeatherMap](https://openweathermap.org/api)
2. Enter the key when prompted during installation
3. Weather data updates automatically every 15 minutes

You can add or update the API key later by editing `/etc/gps-tracker/config.env`

## 📦 Package Contents

```
boat-tracker_installer/
├── install.sh           # Interactive installer script
├── app.py               # Main GPS Tracker application
├── requirements.txt     # Python dependencies
├── init_db.py          # Database initialization script
└── README.md           # This file
```

## ⚙️ Configuration Options

The installer will prompt for:

| Setting | Default | Description |
|---------|---------|-------------|
| **Domain Name** | *(required)* | Your domain (e.g., gps.example.com) |
| **Application Port** | 5001 | Internal port (proxied by Nginx) |
| **Installation Path** | /var/www/gps-tracker-secure | Where to install |
| **SSL Certificate** | Let's Encrypt | Self-signed, Let's Encrypt, or own cert |
| **Weather API Key** | *(optional)* | OpenWeatherMap API key |

## 📍 After Installation

### Access Your GPS Tracker

Visit: `https://your-domain.com`

**Default Admin Credentials:**
- Username: `admin`
- Password: *(shown at end of installation)*

⚠️ **Change the admin password immediately after first login!**

### Features Available

1. **Dashboard** - View GPS tracking map with real-time updates
2. **Float Plan** - Create multi-leg trip plans with waypoints
3. **Weather** - Live weather conditions and radar overlay
4. **Boat Info** - View and manage vessel information
5. **Users** (Admin) - Manage user accounts
6. **Settings** (Admin) - Configure boat info and change passwords

### Submit GPS Data

Use the API endpoint with your generated API key:

```bash
curl -X POST https://your-domain.com/api/gps \
  -H "X-API-Key: YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"latitude": 40.7128, "longitude": -74.0060, "deviceId": "boat-01"}'
```

The API key is shown at the end of installation and saved to:  
`/var/www/gps-tracker-secure/installation_details.txt`

## 🛠️ Management

### Service Commands

```bash
# Restart the application
sudo systemctl restart gps-tracker-secure

# View live logs
sudo journalctl -u gps-tracker-secure -f

# Check service status
sudo systemctl status gps-tracker-secure

# Reload Nginx configuration
sudo systemctl reload nginx
```

### Configuration Files

| File | Purpose |
|------|---------|
| `/etc/systemd/system/gps-tracker-secure.service` | Service configuration |
| `/etc/gps-tracker/config.env` | Environment variables (API keys) |
| `/etc/nginx/sites-available/gps-tracker-secure` | Nginx configuration |
| `/var/www/gps-tracker-secure/gps_tracker.db` | SQLite database |

### Add Weather API Key Later

```bash
# Edit configuration
sudo nano /etc/gps-tracker/config.env

# Add or update:
# OPENWEATHER_API_KEY=your_key_here

# Restart service
sudo systemctl restart gps-tracker-secure
```

### Upgrade to Let's Encrypt

If you installed with self-signed certificates:

```bash
sudo certbot --nginx -d your-domain.com
sudo systemctl reload nginx
```

## 🔒 Security Features

- **HTTPS Encryption** - All traffic encrypted with TLS
- **Authentication Required** - Login required for all pages
- **API Key Protection** - GPS data requires valid API key
- **Rate Limiting** - Protection against abuse
- **Security Headers** - HSTS, CSP, XSS protection
- **Input Validation** - All inputs sanitized
- **Password Hashing** - Secure password storage
- **Systemd Isolation** - Service runs with restricted privileges

## 📊 System Requirements

### Minimum Specifications

- **CPU**: 1 core
- **RAM**: 1GB
- **Storage**: 2GB available space
- **Network**: Internet connection
- **OS**: Ubuntu 20.04+ or Debian 11+

### Recommended for Production

- **CPU**: 2 cores
- **RAM**: 2GB
- **Storage**: 10GB (for GPS data history)
- **Network**: Static IP + domain name
- **Firewall**: Ports 80/443 open

## 🐛 Troubleshooting

### Installation Fails

**Check system compatibility:**
```bash
lsb_release -a  # Verify Ubuntu/Debian
```

**Ensure running as root:**
```bash
sudo bash install.sh  # Use sudo
```

**Check internet connection:**
```bash
ping -c 3 google.com
```

### Service Won't Start

**View error logs:**
```bash
sudo journalctl -u gps-tracker-secure -n 50
```

**Check port availability:**
```bash
sudo lsof -i :5001  # Default port
```

**Verify file permissions:**
```bash
ls -la /var/www/gps-tracker-secure/
```

### Let's Encrypt Certificate Fails

**Requirements:**
- Domain must point to your server's IP
- Port 80 must be accessible from internet
- Server must be reachable at the domain

**Manual certificate:**
```bash
sudo certbot certonly --standalone -d your-domain.com
# Then re-run installer or update Nginx config
```

### Can't Access Website

**Check firewall:**
```bash
sudo ufw status
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
```

**Verify Nginx:**
```bash
sudo nginx -t  # Test configuration
sudo systemctl status nginx
```

**Check DNS:**
```bash
nslookup your-domain.com  # Should resolve to your IP
```

## 📝 Uninstall

To remove the GPS Tracker:

```bash
# Stop and disable service
sudo systemctl stop gps-tracker-secure
sudo systemctl disable gps-tracker-secure

# Remove files
sudo rm -rf /var/www/gps-tracker-secure
sudo rm /etc/systemd/system/gps-tracker-secure.service
sudo rm /etc/nginx/sites-enabled/gps-tracker-secure
sudo rm /etc/nginx/sites-available/gps-tracker-secure
sudo rm -rf /etc/gps-tracker

# Remove user (optional)
sudo userdel gps-tracker

# Reload services
sudo systemctl daemon-reload
sudo systemctl reload nginx
```

## 🔄 Updates

To update your GPS Tracker installation:

1. Backup your database:
   ```bash
   sudo cp /var/www/gps-tracker-secure/gps_tracker.db ~/backup/
   ```

2. Download new version and re-run installer:
   ```bash
   sudo bash install.sh
   ```

The installer will detect existing installation and offer to upgrade.

## 📚 Additional Documentation

Once installed, find these guides in the installation directory:

- `README.md` - Complete application documentation
- `FLOAT_PLAN_GUIDE.md` - Float plan feature guide
- `installation_details.txt` - Your specific configuration

## 🆘 Support

### Common Issues

1. **"Port already in use"** - Change the port during installation
2. **"Domain invalid"** - Ensure domain format is correct (no http://)
3. **"Certificate failed"** - Try self-signed option first
4. **"Permission denied"** - Make sure to use `sudo`

### Getting Help

- Check application logs: `sudo journalctl -u gps-tracker-secure -f`
- Review Nginx logs: `sudo tail -f /var/log/nginx/gps-tracker-error.log`
- Verify installation: `cat /var/www/gps-tracker-secure/installation_details.txt`

## 📄 License

This GPS Tracker application is provided as-is for educational and personal use. Ensure compliance with local maritime and privacy regulations when deploying in production environments.

## 🎉 What's Next?

After installation:

1. **Change Admin Password** - Go to Settings → Change Password
2. **Add Users** - Create accounts for crew members
3. **Configure Boat Info** - Add vessel specifications
4. **Create Float Plan** - Plan your next voyage
5. **Submit GPS Data** - Start tracking your position
6. **Enable Weather** - Add OpenWeatherMap API key

---

**⛵ Ready to set sail? Run `sudo bash install.sh` to begin! ⛵**
