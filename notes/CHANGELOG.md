# 🛡️ GPS Tracker Deployment Package - Changelog

## Latest Version (2026-03-28)

### ✨ **New Features**

#### 🔧 **Custom Fields for Boat Information**
- **Freeform Custom Fields** - Add unlimited custom name/value fields to boat info
- **Proper Relational Storage** - New `boat_custom_fields` table (not JSON in a TEXT column)
- **Dynamic UI** - Add/remove custom fields on the fly in Settings
- **Display Integration** - Custom fields shown on Boat Info page with teal accent

#### 🚀 **Git-Based Deployment Pipeline**
- **Production server** (192.168.101.12) now uses git pull for updates
- **`update.sh`** script: backs up DB, pulls from GitHub, restarts service, health check
- **`.gitignore`** keeps runtime files (db, venv, uploads) out of the repo
- **One-command deploy**: `ssh root@192.168.101.12 '/var/www/gps-tracker-secure/update.sh'`

### 🐛 **Bug Fixes**

#### **init_db() Not Running Under Gunicorn**
- `init_db()` was only called in `__main__`, which gunicorn never triggers
- Moved to module load time so new tables are always created on restart
- All statements are idempotent (`CREATE IF NOT EXISTS`) — safe to run every startup

#### **Boat Info Form Losing Values on Save**
- Form `value` attributes used wrong column names (e.g. `boat['length_ft']` vs actual DB column `boat['length']`)
- Fields with mismatched names rendered empty, so saving overwrote real data with blanks
- Fixed all 6 affected fields: length, draft, beam, fuel_tank_size, engine_size, engine_serial

#### **"Error updating boat information" on Save**
- `float('None')` crash when DB stored `None` and Jinja rendered it as the literal string `"None"`
- Added `safe_float()` and `safe_int()` helpers that handle empty strings, `'None'`, and invalid input
- Template values now use `is not none` checks to render empty string instead of `"None"`

#### **Python 3.12+ SyntaxWarning**
- Fixed invalid escape sequence `\[` in Float Plan template JS regex
- Double-escaped backslashes so Python interprets them correctly

---

## Version 2025-10-27

### ✨ **New Features Added**

#### 🗺️ **Map View Persistence**
- **Persistent Map Position** - Map remembers your view position and zoom level across page refreshes
- **localStorage Integration** - Saves map state in browser's localStorage
- **Auto-Restore on Refresh** - Restores previous view instead of auto-centering on latest GPS point
- **Manual Re-center** - "📍 Center on Latest" button remains functional for manual centering
- **Smart Default Behavior** - On first visit (no saved view), auto-centers on latest GPS coordinate
- **Event-Driven Saving** - Map view saved whenever user pans or zooms

**User Benefits:**
- View stays where you position it during the 60-second auto-refresh
- No more jarring jumps to the latest coordinate during data updates
- Better for monitoring multiple areas or reviewing track history
- Seamless user experience across refresh cycles

---

## Previous Version (2025-10-20)

### ✨ **New Features Added**

#### 📊 **Enhanced Settings Page**
- **API Key Display** - Full GPS API key shown with copy-to-clipboard functionality
- **System Statistics** - Real-time display of GPS points, devices, users, and admins
- **System Information** - Server time, security status, and database connectivity
- **Professional UI** - Modern, responsive interface matching the application design
- **Danger Zone** - Secure access to data management operations

#### 🔐 **Session Persistence Fix**
- **Persistent Secret Key** - Flask sessions now survive worker restarts
- **Environment Configuration** - Secret key stored in environment variables
- **No More Logout Issues** - Users stay logged in reliably

#### 🔐 **Password Management System**
- **Self-Service Password Change** - Users can change their own passwords via Settings
- **Admin Password Reset** - Administrators can reset passwords for any user
- **Secure Validation** - Current password verification for changes
- **Auto-Generated Passwords** - Secure random passwords for admin resets
- **Access Control** - Settings page available to all users, admin features restricted

#### 🛠️ **Installation Improvements**
- **Automatic Secret Key Generation** - Install script generates persistent Flask secret keys
- **Enhanced Documentation** - Updated troubleshooting for session issues
- **Environment Management** - Proper handling of configuration variables

### 📁 **Complete Package Contents**

#### **Core Application**
- `app.py` - Complete Flask application (49KB) with all features:
  - User authentication and session management
  - Admin user management interface
  - Enhanced settings page with API key display
  - GPS tracking with OpenStreetMap integration
  - Secure API endpoints with rate limiting
  - Comprehensive error handling and logging

#### **Deployment Tools**
- `install.sh` - One-command installation script with:
  - System dependency installation
  - Python virtual environment setup
  - Database initialization
  - SSL certificate generation
  - Nginx configuration
  - Service creation and startup

#### **Configuration Files**
- `gps-tracker.service` - Systemd service with environment variables
- `nginx-gps-tracker.conf` - Nginx reverse proxy with security headers
- `requirements.txt` - Python dependencies
- `init_db.py` - Database setup and admin user creation

#### **Documentation & Testing**
- `README.md` - Comprehensive installation and usage guide
- `test_client.py` - API testing client for validation
- `CHANGELOG.md` - This change log

### 🚀 **Quick Deployment**

```bash
# Clone or download to your server
cd /path/to/boat-tracker/

# Run the installer (requires root)
sudo bash install.sh

# Follow the prompts and note the admin credentials
```

### 🎯 **What You Get**

1. **Secure HTTPS GPS Tracker** with self-signed certificates
2. **User Authentication System** with admin and regular user roles  
3. **API Key Management** via the settings page
4. **Real-time GPS Mapping** with interactive OpenStreetMap
5. **Multiple Data Formats** - JSON and NMEA sentence support
6. **Production Ready** - Systemd service, Nginx proxy, security headers
7. **Easy Testing** - Included test client for API validation

### 🔧 **Settings Page Features**

The enhanced settings page now includes:

- **📡 API Configuration**
  - Full API key display with copy button
  - List of available endpoints
  
- **📊 System Statistics**  
  - GPS points stored
  - Unique devices tracked
  - Total users and admins
  
- **🔧 System Information**
  - Current server time
  - Security mode status
  - Database connection status
  
- **⚠️ Danger Zone**
  - Data management operations
  - Clear all GPS data function

### 🛡️ **Security Enhancements**

- **Persistent Sessions** - No more unexpected logouts
- **Environment Secrets** - API keys and Flask secrets in environment variables
- **Rate Limiting** - Protection against API abuse
- **Input Validation** - Comprehensive data sanitization
- **HTTPS Enforcement** - SSL/TLS with security headers

### 📝 **Installation Notes**

- **Tested On**: Ubuntu/Debian Linux systems
- **Requirements**: Root access, Python 3, basic networking
- **Domain Setup**: Update domain name in configuration files as needed
- **SSL Certificates**: Self-signed by default, ready for Let's Encrypt
- **Database**: SQLite for simplicity and reliability

### 🎉 **Ready for Production**

This complete package provides everything needed for a secure, professional GPS tracking system suitable for maritime navigation, fleet management, or personal GPS tracking applications.

**Your enhanced GPS tracker deployment package is complete and ready for any environment!** 🛡️

---

*For support and troubleshooting, see the comprehensive README.md file.*