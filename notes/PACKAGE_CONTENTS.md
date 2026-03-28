# 🛡️ GPS Tracker Deployment Package Contents

**Version:** 2025-10-27  
**Location:** `/home/gary/boat-tracker/`  
**Server:** boat-tracker.grayworkscrafts.com (gps-tracker-secure)

## 📦 Complete File List

### Core Application Files
| File | Size | Description |
|------|------|-------------|
| `app.py` | 90K | Complete Flask application with map persistence feature |
| `init_db.py` | 2.4K | Database initialization script with admin user creation |
| `requirements.txt` | 45B | Python package dependencies |

### Deployment Files
| File | Size | Description |
|------|------|-------------|
| `install.sh` | 6.0K | One-command installation script (executable) |
| `gps-tracker.service` | 556B | Systemd service configuration |
| `nginx-gps-tracker.conf` | 1.8K | Nginx reverse proxy configuration with SSL |

### Documentation Files
| File | Size | Description |
|------|------|-------------|
| `README.md` | 9.8K | Comprehensive installation and usage guide |
| `CHANGELOG.md` | 5.7K | Version history and feature changelog |
| `UPDATE_NOTES_2025-10-27.md` | 5.2K | Detailed notes for map persistence update |
| `PACKAGE_CONTENTS.md` | This file | Package overview and file listing |

### Testing & Development
| File | Size | Description |
|------|------|-------------|
| `test_client.py` | 6.0K | API testing client (executable) |

## 🎯 Latest Features (2025-10-27)

### Map View Persistence
The latest update adds intelligent map view persistence:
- Map position and zoom level saved in browser localStorage
- View restored on page refresh instead of auto-centering
- "Center on Latest" button for manual re-centering
- Seamless experience during 60-second auto-refresh cycles

## 🚀 Quick Deployment

```bash
# On your target server
cd /path/to/boat-tracker/
sudo bash install.sh
```

The installer will:
1. Install system dependencies (Python, Nginx, SQLite)
2. Create service user and directory structure
3. Set up Python virtual environment
4. Initialize database with random admin password
5. Generate SSL certificates (self-signed)
6. Configure and start all services

## 📝 Post-Installation

### Access the Application
- **URL:** https://your-domain.com
- **Default Admin:** `admin` (password shown during installation)
- **Change Password:** Via Settings page after first login

### Configuration Files on Server
- **Application:** `/var/www/gps-tracker-secure/app.py`
- **Database:** `/var/www/gps-tracker-secure/gps_tracker.db`
- **Service:** `/etc/systemd/system/gps-tracker-secure.service`
- **Nginx:** `/etc/nginx/sites-available/gps-tracker`
- **SSL Certs:** `/etc/ssl/certs/` and `/etc/ssl/private/`

### Service Management
```bash
# Restart application
sudo systemctl restart gps-tracker-secure

# View logs
sudo journalctl -u gps-tracker-secure -f

# Check status
sudo systemctl status gps-tracker-secure
```

## 🔧 Updating the Application

### Deploy Updates to Server
```bash
# From your local machine
sshpass -p 'PASSWORD' scp app.py root@boat-tracker.grayworkscrafts.com:/var/www/gps-tracker-secure/app.py.new

# On the server
ssh root@boat-tracker.grayworkscrafts.com
cd /var/www/gps-tracker-secure
cp app.py app.py.backup-$(date +%Y%m%d-%H%M%S)
mv app.py.new app.py
systemctl restart gps-tracker-secure
```

### Update Local Installer Package
When modifying the application, update these files in `/home/gary/boat-tracker/`:
- `app.py` - Main application code
- `CHANGELOG.md` - Add version entry with changes
- `README.md` - Update features section if needed
- Create `UPDATE_NOTES_YYYY-MM-DD.md` for significant changes

## 📊 Application Features

### Authentication & Security
- User login/logout with session management
- Admin and regular user roles
- Password hashing and secure storage
- API key authentication for GPS data
- Rate limiting and input validation

### GPS Tracking
- Real-time OpenStreetMap display
- **Persistent map view (NEW!)** - Maintains position across refreshes
- Multiple data format support (JSON, NMEA)
- Multi-device tracking
- Track history and route management
- GPX file upload and display

### User Management (Admin)
- Create/delete user accounts
- Password reset functionality
- Role assignment and management
- User activity monitoring

### Settings & Configuration
- API key display with copy-to-clipboard
- System statistics dashboard
- Password change functionality
- Data management operations

## 🛡️ Security Features

- HTTPS/SSL encryption
- Security headers (HSTS, CSP, etc.)
- Session management with persistent secret keys
- API authentication required
- Rate limiting on endpoints
- Input sanitization and validation

## 📡 API Endpoints

### GPS Data Submission
```bash
# JSON format
POST /api/gps
Header: X-API-Key: YOUR_API_KEY
Body: {"latitude": 40.7128, "longitude": -74.0060, "deviceId": "boat-01"}

# NMEA format
POST /api/nmea
Header: X-API-Key: YOUR_API_KEY
Body: $GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47
```

### Health Check
```bash
GET /api/health
# Returns system status and statistics
```

## 🔄 Version History

- **2025-10-27** - Map view persistence feature
- **2025-10-20** - Enhanced settings page, session persistence
- **Previous** - User management, authentication system, GPS tracking

## 📞 Support

For issues:
1. Check service logs: `journalctl -u gps-tracker-secure -f`
2. Review `README.md` troubleshooting section
3. Check backup files in `/var/www/gps-tracker-secure/`
4. See `UPDATE_NOTES_*.md` files for specific update guidance

---

**Complete deployment package with all features ready for production!** 🛡️
