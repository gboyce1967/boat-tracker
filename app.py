#!/usr/bin/env python3
import sqlite3
import json
import re
import hashlib
import secrets
import time
import xml.etree.ElementTree as ET
import threading
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, render_template_string, g, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import urllib.request
import urllib.parse

app = Flask(__name__)

# Security configuration
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max request size (for images)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', 'boat_images')
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# API key for GPS data submission
API_KEY = os.environ.get('GPS_API_KEY', 'your-secure-api-key-change-this')

# OpenWeatherMap API key (get free key from https://openweathermap.org/api)
WEATHER_API_KEY = os.environ.get('OPENWEATHER_API_KEY', '')

# Simple rate limiting
rate_limit_store = {}

# Database configuration
DATABASE = 'gps_tracker.db'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        # GPS coordinates table
        db.execute('''
            CREATE TABLE IF NOT EXISTS gps_coordinates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                device_id TEXT DEFAULT 'unknown',
                remote_ip_hash TEXT,
                source_format TEXT DEFAULT 'json',
                raw_data_hash TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                is_track_point BOOLEAN DEFAULT 1
            )
        ''')
        
        # Track history table for saved tracks
        db.execute('''
            CREATE TABLE IF NOT EXISTS track_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')
        
        # Track points for saved tracks
        db.execute('''
            CREATE TABLE IF NOT EXISTS track_points (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                track_id INTEGER NOT NULL,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                timestamp TEXT,
                sequence_order INTEGER,
                FOREIGN KEY (track_id) REFERENCES track_history(id) ON DELETE CASCADE
            )
        ''')
        
        # GPX routes table
        db.execute('''
            CREATE TABLE IF NOT EXISTS gpx_routes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT,
                filename TEXT,
                uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP,
                uploaded_by INTEGER,
                visible BOOLEAN DEFAULT 1,
                color TEXT DEFAULT '#FF0000',
                FOREIGN KEY (uploaded_by) REFERENCES users(id)
            )
        ''')
        
        # GPX route waypoints
        db.execute('''
            CREATE TABLE IF NOT EXISTS gpx_waypoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                route_id INTEGER NOT NULL,
                name TEXT,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                sequence_order INTEGER,
                FOREIGN KEY (route_id) REFERENCES gpx_routes(id) ON DELETE CASCADE
            )
        ''')
        
        # Weather data table
        db.execute('''
            CREATE TABLE IF NOT EXISTS weather_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                temperature REAL,
                humidity INTEGER,
                pressure REAL,
                wind_speed REAL,
                wind_direction INTEGER,
                visibility REAL,
                weather_main TEXT,
                weather_description TEXT,
                precipitation REAL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        ''')        
        
        # Boat information table
        db.execute('''
            CREATE TABLE IF NOT EXISTS boat_info (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                registration_number TEXT,
                length REAL,
                draft REAL,
                beam REAL,
                fuel_tank_size REAL,
                engine_size TEXT,
                engine_serial TEXT,
                bin_number TEXT,
                color TEXT,
                model TEXT,
                year INTEGER,
                boat_image_filename TEXT,
                custom_fields TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER,
                FOREIGN KEY (updated_by) REFERENCES users(id)
            )
        ''')
        
        # Float plan table
        db.execute('''
            CREATE TABLE IF NOT EXISTS float_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (created_by) REFERENCES users(id)
            )
        ''')
        
        # Float plan legs/waypoints
        db.execute('''
            CREATE TABLE IF NOT EXISTS float_plan_legs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER NOT NULL,
                leg_order INTEGER NOT NULL,
                location_name TEXT,
                location_type TEXT DEFAULT 'waypoint',
                address TEXT,
                latitude REAL,
                longitude REAL,
                arrival_time TEXT,
                departure_time TEXT,
                phone TEXT,
                vhf_channel TEXT,
                website TEXT,
                notes TEXT,
                approach_instructions TEXT,
                speed_estimate TEXT,
                fuel_consumption TEXT,
                travel_duration TEXT,
                FOREIGN KEY (plan_id) REFERENCES float_plans(id) ON DELETE CASCADE
            )
        ''')
        
        # Users table for authentication
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin BOOLEAN DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            )
        ''')
        
        db.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON gps_coordinates(timestamp)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_device_id ON gps_coordinates(device_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_username ON users(username)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_track_id ON track_points(track_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_route_id ON gpx_waypoints(route_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_weather_timestamp ON weather_data(timestamp)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_plan_id ON float_plan_legs(plan_id)')
        db.execute('CREATE INDEX IF NOT EXISTS idx_leg_order ON float_plan_legs(leg_order)')
        
        # Create default admin user if no users exist
        cursor = db.execute('SELECT COUNT(*) as count FROM users')
        user_count = cursor.fetchone()['count']
        
        if user_count == 0:
            admin_password = secrets.token_urlsafe(12)  # Generate random password
            password_hash = generate_password_hash(admin_password)
            db.execute('''
                INSERT INTO users (username, email, password_hash, is_admin)
                VALUES (?, ?, ?, ?)
            ''', ('admin', 'admin@gps-tracker.local', password_hash, 1))
            print(f"🔐 Default admin user created:")
            print(f"   Username: admin")
            print(f"   Password: {admin_password}")
            print(f"   Please change this password after first login!")
        
        db.commit()

def require_login(f):
    """Decorator to require login for routes"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def require_admin(f):
    """Decorator to require admin privileges"""
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],))
        user = cursor.fetchone()
        
        if not user or not user['is_admin']:
            flash('Admin privileges required', 'error')
            return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    decorated_function.__name__ = f.__name__
    return decorated_function

def hash_data(data):
    """Hash sensitive data for storage"""
    return hashlib.sha256(str(data).encode()).hexdigest()[:16]

def check_rate_limit(ip, limit=10, window=60):
    """Simple rate limiting"""
    now = time.time()
    if ip not in rate_limit_store:
        rate_limit_store[ip] = []
    
    # Clean old requests
    rate_limit_store[ip] = [req_time for req_time in rate_limit_store[ip] if now - req_time < window]
    
    if len(rate_limit_store[ip]) >= limit:
        return False
    
    rate_limit_store[ip].append(now)
    return True

def validate_api_key():
    """Validate API key from request headers"""
    api_key = request.headers.get('X-API-Key') or request.headers.get('Authorization')
    if api_key and api_key.startswith('Bearer '):
        api_key = api_key[7:]  # Remove 'Bearer ' prefix
    return api_key == API_KEY

def sanitize_input(data, max_length=100):
    """Sanitize input data"""
    if not isinstance(data, str):
        data = str(data)
    # Remove potentially dangerous characters
    data = re.sub(r'[<>"\';\&]', '', data)
    return data[:max_length].strip()

def validate_coordinates(lat, lng):
    """Validate GPS coordinates"""
    try:
        lat = float(lat)
        lng = float(lng)
        if lat < -90 or lat > 90 or lng < -180 or lng > 180:
            return None, None
        return lat, lng
    except (ValueError, TypeError):
        return None, None

def parse_gpx_file(gpx_content):
    """Parse GPX file and extract routes and tracks"""
    try:
        root = ET.fromstring(gpx_content)
        # Handle namespace
        ns = {'gpx': 'http://www.topografix.com/GPX/1/1'}
        
        routes = []
        tracks = []
        
        # Parse routes
        for rte in root.findall('.//gpx:rte', ns) or root.findall('.//rte'):
            route = {
                'name': '',
                'description': '',
                'waypoints': []
            }
            
            name_elem = rte.find('gpx:name', ns) or rte.find('name')
            if name_elem is not None and name_elem.text:
                route['name'] = name_elem.text.strip()
            
            desc_elem = rte.find('gpx:desc', ns) or rte.find('desc')
            if desc_elem is not None and desc_elem.text:
                route['description'] = desc_elem.text.strip()
            
            for rtept in rte.findall('.//gpx:rtept', ns) or rte.findall('.//rtept'):
                lat = rtept.get('lat')
                lon = rtept.get('lon')
                if lat and lon:
                    wpt_name_elem = rtept.find('gpx:name', ns) or rtept.find('name')
                    wpt_name = wpt_name_elem.text.strip() if wpt_name_elem is not None and wpt_name_elem.text else ''
                    
                    route['waypoints'].append({
                        'name': wpt_name,
                        'latitude': float(lat),
                        'longitude': float(lon)
                    })
            
            if route['waypoints']:
                routes.append(route)
        
        # Parse tracks
        for trk in root.findall('.//gpx:trk', ns) or root.findall('.//trk'):
            track = {
                'name': '',
                'description': '',
                'points': []
            }
            
            name_elem = trk.find('gpx:name', ns) or trk.find('name')
            if name_elem is not None and name_elem.text:
                track['name'] = name_elem.text.strip()
            
            desc_elem = trk.find('gpx:desc', ns) or trk.find('desc')
            if desc_elem is not None and desc_elem.text:
                track['description'] = desc_elem.text.strip()
            
            for trkseg in trk.findall('.//gpx:trkseg', ns) or trk.findall('.//trkseg'):
                for trkpt in trkseg.findall('.//gpx:trkpt', ns) or trkseg.findall('.//trkpt'):
                    lat = trkpt.get('lat')
                    lon = trkpt.get('lon')
                    if lat and lon:
                        track['points'].append({
                            'latitude': float(lat),
                            'longitude': float(lon)
                        })
            
            if track['points']:
                tracks.append(track)
        
        return routes, tracks
    except Exception as e:
        app.logger.error(f"GPX parsing error: {e}")
        return [], []

def parse_nmea_gps(nmea_sentence):
    """Parse NMEA GPS sentences with validation"""
    try:
        # Sanitize NMEA sentence
        nmea_sentence = re.sub(r'[^A-Za-z0-9,.$*-]', '', nmea_sentence)
        parts = nmea_sentence.strip().split(',')
        
        # Handle GGA sentences
        if parts[0] in ['$GPGGA', '$GNGGA']:
            if len(parts) >= 15 and parts[2] and parts[4]:
                lat_raw = parts[2]
                lat_dir = parts[3]
                lon_raw = parts[4] 
                lon_dir = parts[5]
                
                # Validate format
                if not re.match(r'^\d{4}\.\d+$', lat_raw) or not re.match(r'^\d{5}\.\d+$', lon_raw):
                    return None, None
                
                lat_deg = int(lat_raw[:2])
                lat_min = float(lat_raw[2:])
                latitude = lat_deg + lat_min / 60.0
                if lat_dir == 'S':
                    latitude = -latitude
                    
                lon_deg = int(lon_raw[:3])
                lon_min = float(lon_raw[3:])
                longitude = lon_deg + lon_min / 60.0
                if lon_dir == 'W':
                    longitude = -longitude
                    
                return validate_coordinates(latitude, longitude)
                
        # Handle RMC sentences
        elif parts[0] in ['$GPRMC', '$GNRMC']:
            if len(parts) >= 12 and parts[3] and parts[5]:
                lat_raw = parts[3]
                lat_dir = parts[4]
                lon_raw = parts[5]
                lon_dir = parts[6]
                
                if not re.match(r'^\d{4}\.\d+$', lat_raw) or not re.match(r'^\d{5}\.\d+$', lon_raw):
                    return None, None
                
                lat_deg = int(lat_raw[:2])
                lat_min = float(lat_raw[2:])
                latitude = lat_deg + lat_min / 60.0
                if lat_dir == 'S':
                    latitude = -latitude
                    
                lon_deg = int(lon_raw[:3])
                lon_min = float(lon_raw[3:])
                longitude = lon_deg + lon_min / 60.0
                if lon_dir == 'W':
                    longitude = -longitude
                    
                return validate_coordinates(latitude, longitude)
                
    except (ValueError, IndexError) as e:
        app.logger.warning(f"NMEA parsing error: {e}")
        return None, None
        
    return None, None

def fetch_weather_data(lat, lng):
    """Fetch weather data from OpenWeatherMap API"""
    if not WEATHER_API_KEY:
        app.logger.warning("OpenWeatherMap API key not configured")
        return None
    
    try:
        # Build API URL
        base_url = "https://api.openweathermap.org/data/2.5/weather"
        params = urllib.parse.urlencode({
            'lat': lat,
            'lon': lng,
            'appid': WEATHER_API_KEY,
            'units': 'imperial'  # Fahrenheit, mph for wind
        })
        url = f"{base_url}?{params}"
        
        # Make API request
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode('utf-8'))
        
        # Extract relevant weather data
        weather_info = {
            'temperature': data.get('main', {}).get('temp'),
            'humidity': data.get('main', {}).get('humidity'),
            'pressure': data.get('main', {}).get('pressure'),
            'wind_speed': data.get('wind', {}).get('speed'),
            'wind_direction': data.get('wind', {}).get('deg'),
            'visibility': data.get('visibility', 0) / 1609.34,  # Convert meters to miles
            'weather_main': data.get('weather', [{}])[0].get('main', ''),
            'weather_description': data.get('weather', [{}])[0].get('description', ''),
            'precipitation': data.get('rain', {}).get('1h', 0) or data.get('snow', {}).get('1h', 0)
        }
        
        return weather_info
    
    except Exception as e:
        app.logger.error(f"Error fetching weather data: {e}")
        return None

def store_weather_data(lat, lng, weather_info):
    """Store weather data in database"""
    try:
        with app.app_context():
            db = get_db()
            timestamp = datetime.now().isoformat()
            
            db.execute('''
                INSERT INTO weather_data 
                (latitude, longitude, timestamp, temperature, humidity, pressure, 
                 wind_speed, wind_direction, visibility, weather_main, weather_description, precipitation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (lat, lng, timestamp, weather_info['temperature'], weather_info['humidity'],
                  weather_info['pressure'], weather_info['wind_speed'], weather_info['wind_direction'],
                  weather_info['visibility'], weather_info['weather_main'], 
                  weather_info['weather_description'], weather_info['precipitation']))
            
            db.commit()
            app.logger.info(f"Weather data stored for location ({lat}, {lng})")
    
    except Exception as e:
        app.logger.error(f"Error storing weather data: {e}")

def update_weather_task():
    """Background task to update weather every 15 minutes"""
    while True:
        try:
            time.sleep(900)  # 15 minutes
            
            with app.app_context():
                db = get_db()
                
                # Get latest GPS coordinates
                cursor = db.execute('''
                    SELECT latitude, longitude 
                    FROM gps_coordinates 
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''')
                
                result = cursor.fetchone()
                if result:
                    lat, lng = result['latitude'], result['longitude']
                    app.logger.info(f"Updating weather for location ({lat}, {lng})")
                    
                    # Fetch and store weather data
                    weather_info = fetch_weather_data(lat, lng)
                    if weather_info:
                        store_weather_data(lat, lng, weather_info)
                else:
                    app.logger.info("No GPS coordinates available for weather update")
        
        except Exception as e:
            app.logger.error(f"Error in weather update task: {e}")

# Error handlers
@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({'error': 'Forbidden'}), 403

@app.errorhandler(413)
def payload_too_large(error):
    return jsonify({'error': 'Request too large'}), 413

@app.errorhandler(429)
def too_many_requests(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

# Login template
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: white; padding: 40px; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); width: 100%; max-width: 400px; }
        .login-header { text-align: center; margin-bottom: 30px; }
        .login-header h1 { color: #333; margin-bottom: 10px; }
        .login-header p { color: #666; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; color: #333; font-weight: 500; }
        .form-group input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; }
        .form-group input:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 2px rgba(102,126,234,0.2); }
        .login-button { width: 100%; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; padding: 14px; border-radius: 8px; font-size: 16px; cursor: pointer; transition: transform 0.2s; }
        .login-button:hover { transform: translateY(-2px); }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 6px; }
        .alert-error { background: #fee; border: 1px solid #fcc; color: #c33; }
        .alert-success { background: #efe; border: 1px solid #cfc; color: #3c3; }
        .footer { text-align: center; margin-top: 20px; font-size: 12px; color: #666; }
        .admin-note { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 12px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1>🛡️ GPS Tracker</h1>
            <p>Secure Maritime Navigation System</p>
        </div>
        
        {% if first_login %}
        <div class="admin-note">
            <strong>🔐 First Time Setup:</strong><br>
            Use the default admin credentials displayed in the server console to login, then create your own account.
        </div>
        {% endif %}
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'error' if category == 'error' else 'success' }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <form method="POST">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="login-button">Sign In</button>
        </form>
        
        <div class="footer">
            Secure GPS Tracking System v2.0
        </div>
    </div>
</body>
</html>
'''

# Dashboard template
DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: white; padding: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .nav-brand { font-size: 20px; font-weight: bold; color: #333; }
        .nav-menu { display: flex; gap: 20px; align-items: center; }
        .nav-menu a { color: #666; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav-menu a:hover, .nav-menu a.active { background: #f0f0f0; color: #333; }
        .nav-user { color: #666; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .auth-warning { background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .security-info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; color: #007bff; }
        .stat-label { color: #666; margin-top: 5px; }
        .controls { display: flex; gap: 15px; align-items: center; margin-bottom: 20px; flex-wrap: wrap; }
        .controls-section { background: white; padding: 15px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .controls-row { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-bottom: 10px; }
        .controls-row:last-child { margin-bottom: 0; }
        .control-group { display: flex; gap: 10px; align-items: center; }
        .control-label { font-weight: 500; color: #333; margin-right: 10px; }
        button, .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; font-size: 14px; text-decoration: none; display: inline-block; }
        button:hover, .btn:hover { background: #0056b3; }
        button:disabled { background: #ccc; cursor: not-allowed; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-warning { background: #ffc107; color: #000; }
        .btn-warning:hover { background: #e0a800; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-small { padding: 6px 12px; font-size: 12px; }
        input[type="file"] { padding: 8px; border: 1px solid #ddd; border-radius: 5px; }
        select { padding: 8px; border: 1px solid #ddd; border-radius: 5px; background: white; cursor: pointer; }
        .modal { display: none; position: fixed; z-index: 10000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); }
        .modal-content { background: white; margin: 10% auto; padding: 25px; border-radius: 10px; width: 90%; max-width: 500px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }
        .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .modal-header h3 { margin: 0; }
        .close { font-size: 28px; font-weight: bold; cursor: pointer; color: #666; }
        .close:hover { color: #000; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 500; }
        .form-group input, .form-group textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .list-item { padding: 10px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .list-item:hover { background: #f8f9fa; }
        .list-item-info { flex: 1; }
        .list-item-name { font-weight: 500; color: #333; }
        .list-item-details { font-size: 12px; color: #666; margin-top: 4px; }
        .list-item-actions { display: flex; gap: 8px; }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 6px; }
        .alert-error { background: #fee; border: 1px solid #fcc; color: #c33; }
        .alert-success { background: #efe; border: 1px solid #cfc; color: #3c3; }
        .info { display: flex; gap: 20px; color: #666; font-size: 14px; }
        #map { height: 500px; width: 100%; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .coordinates-panel { background: white; padding: 20px; border-radius: 10px; margin-top: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-height: 400px; overflow-y: auto; }
        .coordinate-item { border-bottom: 1px solid #eee; padding: 10px 0; }
        .device-id { font-weight: bold; color: #007bff; }
    </style>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">🛡️ GPS Tracker</div>
            <div class="nav-menu">
                <a href="{{ url_for('dashboard') }}" class="active">Dashboard</a>
                <a href="{{ url_for('weather') }}">Weather</a>
                <a href="{{ url_for('boat_info') }}">Boat Info</a>
                <a href="{{ url_for('float_plan') }}">Float Plan</a>
                {% if current_user.is_admin %}
                <a href="{{ url_for('users') }}">Users</a>
                <a href="{{ url_for('settings') }}">Settings</a>
                {% endif %}
                <span class="nav-user">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'error' if category == 'error' else 'success' }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="auth-warning">
            <strong>🔐 Authenticated Session:</strong> You are logged in as {{ current_user.username }}
            {% if current_user.is_admin %} (Administrator){% endif %}
        </div>
        
        <div class="security-info">
            <strong>🛡️ System Status:</strong> All security features are active. API authentication required for GPS data submission.
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{{ marker_count }}</div>
                <div class="stat-label">GPS Points</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ unique_devices }}</div>
                <div class="stat-label">Devices</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ user_count }}</div>
                <div class="stat-label">Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{{ last_update }}</div>
                <div class="stat-label">Last Update</div>
            </div>
        </div>
        
        <div class="controls-section">
            <div class="controls-row">
                <span class="control-label">🗺️ Map Controls:</span>
                <button onclick="centerOnLatest()">📍 Center on Latest</button>
                <button onclick="window.location.reload()">🔄 Refresh</button>
                <button onclick="toggleTrackVisibility()" id="toggle-track-btn">👁️ Hide Track</button>
            </div>
            
            <div class="controls-row">
                <span class="control-label">📈 Track Management:</span>
                <button onclick="clearTrack()" class="btn-warning">🧹 Clear Track</button>
                <button onclick="showSaveTrackModal()" class="btn-success">💾 Save Track</button>
                <button onclick="showLoadTrackModal()">📂 Load Track</button>
            </div>
            
            <div class="controls-row">
                <span class="control-label">🧭 Routes:</span>
                <button onclick="document.getElementById('gpx-file-input').click()" class="btn-success">📤 Upload GPX</button>
                <input type="file" id="gpx-file-input" accept=".gpx" style="display: none;" onchange="uploadGPX(event)">
                <button onclick="showRoutesModal()">📋 Manage Routes</button>
            </div>
            
            {% if current_user.is_admin %}
            <div class="controls-row">
                <span class="control-label">⚙️ Admin:</span>
                <a href="{{ url_for('clear_data') }}" class="btn btn-danger" onclick="return confirm('Clear all GPS data?')">🗑️ Clear All Data</a>
            </div>
            {% endif %}
        </div>
        
        <div id="map"></div>
        
        <!-- Save Track Modal -->
        <div id="save-track-modal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>💾 Save Current Track</h3>
                    <span class="close" onclick="closeSaveTrackModal()">&times;</span>
                </div>
                <div class="form-group">
                    <label>Track Name:</label>
                    <input type="text" id="track-name" placeholder="e.g., Morning Sail">
                </div>
                <div class="form-group">
                    <label>Description (optional):</label>
                    <textarea id="track-description" rows="3" placeholder="Notes about this track..."></textarea>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button onclick="saveTrack()" class="btn-success">Save</button>
                    <button onclick="closeSaveTrackModal()">Cancel</button>
                </div>
            </div>
        </div>
        
        <!-- Load Track Modal -->
        <div id="load-track-modal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>📂 Load Saved Track</h3>
                    <span class="close" onclick="closeLoadTrackModal()">&times;</span>
                </div>
                <div id="saved-tracks-list" style="max-height: 400px; overflow-y: auto;">
                    <p style="text-align: center; color: #666;">Loading tracks...</p>
                </div>
            </div>
        </div>
        
        <!-- Routes Management Modal -->
        <div id="routes-modal" class="modal">
            <div class="modal-content">
                <div class="modal-header">
                    <h3>🧭 Manage Routes</h3>
                    <span class="close" onclick="closeRoutesModal()">&times;</span>
                </div>
                <div id="routes-list" style="max-height: 400px; overflow-y: auto;">
                    <p style="text-align: center; color: #666;">Loading routes...</p>
                </div>
            </div>
        </div>
        
        <div class="coordinates-panel">
            <h3>Recent GPS Coordinates</h3>
            <div>
                {% if coordinates %}
                    {% for coord in coordinates %}
                    <div class="coordinate-item">
                        <div class="coordinate-header">
                            <span class="device-id">{{ coord.device_id }}</span>
                            <span class="timestamp">{{ coord.timestamp }}</span>
                        </div>
                        <div class="coordinates">
                            {{ "%.6f"|format(coord.latitude) }}, {{ "%.6f"|format(coord.longitude) }}
                        </div>
                        <div class="source">Source: {{ coord.source_format }}</div>
                    </div>
                    {% endfor %}
                {% else %}
                    <p>No GPS coordinates available</p>
                {% endif %}
            </div>
        </div>
    </div>

    <script>
        let map;
        let markers = [];
        let trackPolyline = null;
        let trackVisible = true;
        let routeLayers = {};
        
        function initMap() {
            const coordinates = {{ coordinates_json|safe }};
            
            // Try to restore previous map view from localStorage
            const savedView = localStorage.getItem('mapView');
            let center = [40.7128, -74.0060];
            let zoom = 10;
            
            if (savedView) {
                try {
                    const view = JSON.parse(savedView);
                    center = view.center;
                    zoom = view.zoom;
                } catch (e) {
                    console.error('Error parsing saved map view:', e);
                }
            } else if (coordinates && coordinates.length > 0) {
                // Only auto-center on first load when no saved view exists
                const latest = coordinates[coordinates.length - 1];
                center = [latest.latitude, latest.longitude];
                zoom = 15;
            }
            
            map = L.map('map').setView(center, zoom);
            
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© OpenStreetMap contributors'
            }).addTo(map);
            
            // Save map view whenever user moves or zooms
            map.on('moveend', saveMapView);
            map.on('zoomend', saveMapView);
            
            // Draw track polyline
            if (coordinates.length > 1) {
                drawTrack(coordinates);
            }
            
            // Add markers
            coordinates.forEach(coord => addMarker(coord));
            
            // Load and display routes
            loadRoutes();
            
            // Auto-refresh every 60 seconds
            setInterval(() => {
                saveMapView(); // Save before reload
                window.location.reload();
            }, 60000);
        }
        
        function saveMapView() {
            if (map) {
                const center = map.getCenter();
                const zoom = map.getZoom();
                localStorage.setItem('mapView', JSON.stringify({
                    center: [center.lat, center.lng],
                    zoom: zoom
                }));
            }
        }
        
        function drawTrack(coordinates) {
            const latLngs = coordinates.map(c => [c.latitude, c.longitude]);
            
            if (trackPolyline) {
                trackPolyline.remove();
            }
            
            trackPolyline = L.polyline(latLngs, {
                color: '#007bff',
                weight: 3,
                opacity: 0.7
            }).addTo(map);
        }
        
        function toggleTrackVisibility() {
            const btn = document.getElementById('toggle-track-btn');
            
            if (trackVisible) {
                if (trackPolyline) trackPolyline.remove();
                btn.textContent = '👁️ Show Track';
                trackVisible = false;
            } else {
                if (trackPolyline) trackPolyline.addTo(map);
                btn.textContent = '👁️ Hide Track';
                trackVisible = true;
            }
        }
        
        function addMarker(coord) {
            // Create custom boat SVG icon
            const boatIcon = L.divIcon({
                html: `<svg width="24" height="24" viewBox="0 0 24 24" fill="#007bff" style="filter: drop-shadow(2px 2px 4px rgba(0,0,0,0.5));">
                    <path d="M2.5 19h19l-1.5-5h-16l-1.5 5zm1.96-2h15.08l.6 2H3.86l.6-2zM12 10.5c1.25 0 2.29-.54 3.04-1.28L17.5 12H6.5l2.46-2.78c.75.74 1.79 1.28 3.04 1.28zM12 2L8.5 7.5h7L12 2z"/>
                </svg>`,
                className: 'boat-marker',
                iconSize: [30, 30],
                iconAnchor: [15, 25]
            });
            
            const marker = L.marker([coord.latitude, coord.longitude], { icon: boatIcon })
                .addTo(map)
                .bindPopup(`
                    <div class="info-window">
                        <h4>⛵ Vessel Location</h4>
                        <p><strong>Device:</strong> ${coord.device_id}</p>
                        <p><strong>Coordinates:</strong> ${coord.latitude.toFixed(6)}, ${coord.longitude.toFixed(6)}</p>
                        <p><strong>Time:</strong> ${new Date(coord.timestamp).toLocaleString()}</p>
                        <p><strong>Source:</strong> ${coord.source_format}</p>
                    </div>
                `);
            
            markers.push(marker);
        }
        
        function centerOnLatest() {
            if (markers.length > 0) {
                const latestMarker = markers[markers.length - 1];
                map.setView(latestMarker.getLatLng(), 15);
            }
        }
        
        // Track management functions
        function clearTrack() {
            if (!confirm('Clear the current track? This will hide the track line but keep GPS points.')) return;
            
            fetch('/api/track/clear', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Track cleared');
                    window.location.reload();
                } else {
                    alert('❌ Error: ' + data.message);
                }
            })
            .catch(e => alert('❌ Error clearing track'));
        }
        
        function showSaveTrackModal() {
            document.getElementById('save-track-modal').style.display = 'block';
            document.getElementById('track-name').value = 'Track ' + new Date().toLocaleString();
        }
        
        function closeSaveTrackModal() {
            document.getElementById('save-track-modal').style.display = 'none';
        }
        
        function saveTrack() {
            const name = document.getElementById('track-name').value;
            const description = document.getElementById('track-description').value;
            
            if (!name.trim()) {
                alert('Please enter a track name');
                return;
            }
            
            fetch('/api/track/save', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name, description})
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert(`✅ ${data.message} (${data.points_saved} points)`);
                    closeSaveTrackModal();
                } else {
                    alert('❌ ' + data.message);
                }
            })
            .catch(e => alert('❌ Error saving track'));
        }
        
        function showLoadTrackModal() {
            document.getElementById('load-track-modal').style.display = 'block';
            loadSavedTracks();
        }
        
        function closeLoadTrackModal() {
            document.getElementById('load-track-modal').style.display = 'none';
        }
        
        function loadSavedTracks() {
            fetch('/api/track/list')
            .then(r => r.json())
            .then(data => {
                const list = document.getElementById('saved-tracks-list');
                
                if (!data.tracks || data.tracks.length === 0) {
                    list.innerHTML = '<p style="text-align: center; color: #666;">No saved tracks</p>';
                    return;
                }
                
                list.innerHTML = data.tracks.map(t => `
                    <div class="list-item">
                        <div class="list-item-info">
                            <div class="list-item-name">${t.name}</div>
                            <div class="list-item-details">
                                ${t.point_count} points • ${new Date(t.created_at).toLocaleString()} • by ${t.username}
                            </div>
                        </div>
                        <div class="list-item-actions">
                            <button class="btn-small" onclick="viewTrack(${t.id})">View</button>
                            <button class="btn-small btn-danger" onclick="deleteTrack(${t.id})">Delete</button>
                        </div>
                    </div>
                `).join('');
            })
            .catch(e => {
                document.getElementById('saved-tracks-list').innerHTML = 
                    '<p style="text-align: center; color: #c33;">Error loading tracks</p>';
            });
        }
        
        function viewTrack(trackId) {
            fetch(`/api/track/${trackId}`)
            .then(r => r.json())
            .then(data => {
                if (data.points && data.points.length > 0) {
                    // Draw track on map
                    const latLngs = data.points.map(p => [p.latitude, p.longitude]);
                    const viewPolyline = L.polyline(latLngs, {
                        color: '#28a745',
                        weight: 3,
                        opacity: 0.8
                    }).addTo(map);
                    
                    map.fitBounds(viewPolyline.getBounds());
                    closeLoadTrackModal();
                }
            })
            .catch(e => alert('❌ Error loading track'));
        }
        
        function deleteTrack(trackId) {
            if (!confirm('Delete this track?')) return;
            
            fetch(`/api/track/${trackId}`, {method: 'DELETE'})
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    loadSavedTracks();
                } else {
                    alert('❌ ' + data.message);
                }
            })
            .catch(e => alert('❌ Error deleting track'));
        }
        
        // Route management functions
        function uploadGPX(event) {
            const file = event.target.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            fetch('/api/route/upload', {
                method: 'POST',
                body: formData
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert(`✅ ${data.message}`);
                    loadRoutes();
                } else {
                    alert('❌ ' + data.message);
                }
            })
            .catch(e => alert('❌ Error uploading GPX file'))
            .finally(() => {
                event.target.value = '';  // Reset file input
            });
        }
        
        function showRoutesModal() {
            document.getElementById('routes-modal').style.display = 'block';
            loadRoutesList();
        }
        
        function closeRoutesModal() {
            document.getElementById('routes-modal').style.display = 'none';
        }
        
        function loadRoutes() {
            fetch('/api/route/list')
            .then(r => r.json())
            .then(data => {
                if (data.routes) {
                    data.routes.forEach(route => {
                        if (route.visible) {
                            displayRoute(route.id);
                        }
                    });
                }
            })
            .catch(e => console.error('Error loading routes:', e));
        }
        
        function loadRoutesList() {
            fetch('/api/route/list')
            .then(r => r.json())
            .then(data => {
                const list = document.getElementById('routes-list');
                
                if (!data.routes || data.routes.length === 0) {
                    list.innerHTML = '<p style="text-align: center; color: #666;">No routes uploaded</p>';
                    return;
                }
                
                list.innerHTML = data.routes.map(r => `
                    <div class="list-item">
                        <div class="list-item-info">
                            <div class="list-item-name">${r.name}</div>
                            <div class="list-item-details">
                                ${r.waypoint_count} points • ${new Date(r.uploaded_at).toLocaleString()} • by ${r.username}
                            </div>
                        </div>
                        <div class="list-item-actions">
                            <button class="btn-small ${r.visible ? 'btn-warning' : 'btn-success'}" 
                                    onclick="toggleRoute(${r.id})">
                                ${r.visible ? '👁️ Hide' : '👁️ Show'}
                            </button>
                            <button class="btn-small btn-danger" onclick="deleteRoute(${r.id})">Delete</button>
                        </div>
                    </div>
                `).join('');
            })
            .catch(e => {
                document.getElementById('routes-list').innerHTML = 
                    '<p style="text-align: center; color: #c33;">Error loading routes</p>';
            });
        }
        
        function displayRoute(routeId) {
            fetch(`/api/route/${routeId}`)
            .then(r => r.json())
            .then(data => {
                if (data.waypoints && data.waypoints.length > 0) {
                    const latLngs = data.waypoints.map(w => [w.latitude, w.longitude]);
                    
                    // Remove existing layer if present
                    if (routeLayers[routeId]) {
                        routeLayers[routeId].remove();
                    }
                    
                    const color = data.route.color || '#FF0000';
                    routeLayers[routeId] = L.polyline(latLngs, {
                        color: color,
                        weight: 4,
                        opacity: 0.8,
                        dashArray: '10, 10'
                    }).addTo(map);
                    
                    // Add waypoint markers
                    data.waypoints.forEach((wpt, idx) => {
                        if (wpt.name) {
                            L.marker([wpt.latitude, wpt.longitude])
                                .bindPopup(`<strong>${wpt.name}</strong><br>${data.route.name}`)
                                .addTo(map);
                        }
                    });
                }
            })
            .catch(e => console.error('Error displaying route:', e));
        }
        
        function toggleRoute(routeId) {
            fetch(`/api/route/${routeId}/toggle`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'}
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    if (data.visible) {
                        displayRoute(routeId);
                    } else {
                        if (routeLayers[routeId]) {
                            routeLayers[routeId].remove();
                            delete routeLayers[routeId];
                        }
                    }
                    loadRoutesList();
                }
            })
            .catch(e => alert('❌ Error toggling route'));
        }
        
        function deleteRoute(routeId) {
            if (!confirm('Delete this route?')) return;
            
            fetch(`/api/route/${routeId}`, {method: 'DELETE'})
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    if (routeLayers[routeId]) {
                        routeLayers[routeId].remove();
                        delete routeLayers[routeId];
                    }
                    loadRoutesList();
                } else {
                    alert('❌ ' + data.message);
                }
            })
            .catch(e => alert('❌ Error deleting route'));
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            if (event.target.classList.contains('modal')) {
                event.target.style.display = 'none';
            }
        }
        
        document.addEventListener('DOMContentLoaded', initMap);
    </script>
</body>
</html>
'''

# Settings Template
SETTINGS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - Settings</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: white; padding: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .nav-brand { font-size: 20px; font-weight: bold; color: #333; }
        .nav-menu { display: flex; gap: 20px; align-items: center; }
        .nav-menu a { color: #666; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav-menu a:hover, .nav-menu a.active { background: #f0f0f0; color: #333; }
        .nav-user { color: #666; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 6px; }
        .alert-error { background: #fee; border: 1px solid #fcc; color: #c33; }
        .alert-success { background: #efe; border: 1px solid #cfc; color: #3c3; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; }
        .setting-item { display: flex; justify-content: space-between; align-items: center; padding: 15px 0; border-bottom: 1px solid #eee; }
        .setting-item:last-child { border-bottom: none; }
        .setting-label { font-weight: 500; color: #333; }
        .setting-description { font-size: 14px; color: #666; margin-top: 4px; }
        .setting-value { font-family: 'Monaco', 'Menlo', monospace; background: #f8f9fa; padding: 8px 12px; border-radius: 4px; border: 1px solid #e9ecef; font-size: 14px; }
        .api-key-container { display: flex; gap: 10px; align-items: center; }
        .copy-btn { background: #007bff; color: white; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .copy-btn:hover { background: #0056b3; }
        .stats-section h3 { margin-bottom: 15px; color: #333; }
        .stat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
        .stat-item { text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: bold; color: #007bff; }
        .stat-label { font-size: 14px; color: #666; margin-top: 5px; }
        .danger-zone { border: 1px solid #dc3545; border-radius: 8px; }
        .danger-zone h3 { background: #dc3545; color: white; padding: 10px 15px; margin: -20px -20px 15px -20px; border-radius: 7px 7px 0 0; }
        .btn-danger { background: #dc3545; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn-danger:hover { background: #c82333; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">🛡️ GPS Tracker</div>
            <div class="nav-menu">
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('weather') }}">Weather</a>
                <a href="{{ url_for('boat_info') }}">Boat Info</a>
                <a href="{{ url_for('float_plan') }}">Float Plan</a>
                {% if current_user.is_admin %}
                <a href="{{ url_for('users') }}">Users</a>
                <a href="{{ url_for('settings') }}" class="active">Settings</a>
                {% endif %}
                <span class="nav-user">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <h1>System Settings</h1>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'error' if category == 'error' else 'success' }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="settings-grid">
            {% if current_user.is_admin %}
            <div class="card">
                <h3>📡 API Configuration</h3>
                <div class="setting-item">
                    <div>
                        <div class="setting-label">GPS API Key</div>
                        <div class="setting-description">Use this key for GPS data submission via API endpoints</div>
                    </div>
                    <div class="api-key-container">
                        <input type="text" class="setting-value" id="api-key" value="{{ api_key }}" readonly style="min-width: 300px;">
                        <button class="copy-btn" onclick="copyToClipboard('api-key')">Copy</button>
                    </div>
                </div>
                <div class="setting-item">
                    <div>
                        <div class="setting-label">API Endpoints</div>
                        <div class="setting-description">Available endpoints for GPS data submission</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: #666;">
                            • /api/gps (JSON)<br>
                            • /api/nmea (NMEA)<br>
                            • /api/bareboat<br>
                            • /api/health
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card stats-section">
                <h3>📊 System Statistics</h3>
                <div class="stat-grid">
                    <div class="stat-item">
                        <div class="stat-number">{{ stats.gps_points }}</div>
                        <div class="stat-label">GPS Points</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{{ stats.unique_devices }}</div>
                        <div class="stat-label">Devices</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{{ stats.total_users }}</div>
                        <div class="stat-label">Users</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{{ stats.admin_users }}</div>
                        <div class="stat-label">Admins</div>
                    </div>
                </div>
            </div>
            {% endif %}
        </div>
        
        {% if current_user.is_admin %}
        <div class="card">
            <h3>⛵ Boat Information</h3>
            <div class="setting-item">
                <div>
                    <div class="setting-label">Boat Details</div>
                    <div class="setting-description">Manage boat information and specifications</div>
                </div>
                <button class="copy-btn" onclick="toggleBoatForm()" id="boat-toggle">Edit Boat Info</button>
            </div>
            <div id="boat-form" style="display: none; margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
                <form method="POST" action="{{ url_for('update_boat_info') }}" enctype="multipart/form-data">
                    <div style="margin-bottom: 15px; grid-column: span 2;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">Boat Image:</label>
                        {% if boat and boat['boat_image_filename'] %}
                        <div style="margin-bottom: 10px;">
                            <img src="{{ url_for('boat_image', filename=boat['boat_image_filename']) }}" alt="Current boat image" style="max-width: 200px; max-height: 150px; border-radius: 8px; border: 2px solid #ddd;">
                            <div style="font-size: 12px; color: #666; margin-top: 5px;">Current image</div>
                        </div>
                        {% endif %}
                        <input type="file" name="boat_image" accept="image/*" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        <div style="font-size: 12px; color: #666; margin-top: 5px;">Upload a new image (optional). Accepted formats: JPG, PNG, GIF, WEBP. Max size: 10MB</div>
                    </div>
                    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Registration Number:</label>
                            <input type="text" name="registration_number" value="{{ boat['registration_number'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">BIN Number:</label>
                            <input type="text" name="bin_number" value="{{ boat['bin_number'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Model:</label>
                            <input type="text" name="model" value="{{ boat['model'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Year:</label>
                            <input type="text" name="year" value="{{ boat['year'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Color:</label>
                            <input type="text" name="color" value="{{ boat['color'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Length (ft):</label>
                            <input type="text" name="length_ft" value="{{ boat['length_ft'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Draft (ft):</label>
                            <input type="text" name="draft_ft" value="{{ boat['draft_ft'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Beam (ft):</label>
                            <input type="text" name="beam_ft" value="{{ boat['beam_ft'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Fuel Tank Size (gal):</label>
                            <input type="text" name="fuel_tank_size_gal" value="{{ boat['fuel_tank_size_gal'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Engine Size (hp):</label>
                            <input type="text" name="engine_size_hp" value="{{ boat['engine_size_hp'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                        <div style="margin-bottom: 10px; grid-column: span 2;">
                            <label style="display: block; margin-bottom: 5px; font-weight: 500;">Engine Serial Number:</label>
                            <input type="text" name="engine_serial_number" value="{{ boat['engine_serial_number'] if boat else '' }}" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px; margin-top: 15px;">
                        <button type="submit" style="background: #28a745; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">Save Boat Info</button>
                        <button type="button" onclick="toggleBoatForm()" style="background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">Cancel</button>
                    </div>
                </form>
            </div>
        </div>
        {% endif %}
        
        <div class="card">
            <h3>🔐 Account Management</h3>
            <div class="setting-item">
                <div>
                    <div class="setting-label">Change Password</div>
                    <div class="setting-description">Update your account password</div>
                </div>
                <button class="copy-btn" onclick="togglePasswordForm()" id="password-toggle">Change Password</button>
            </div>
            <div id="password-form" style="display: none; margin-top: 15px; padding: 15px; background: #f8f9fa; border-radius: 6px;">
                <form method="POST" action="{{ url_for('change_password') }}">
                    <div style="margin-bottom: 10px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">Current Password:</label>
                        <input type="password" name="current_password" required style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    </div>
                    <div style="margin-bottom: 10px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">New Password:</label>
                        <input type="password" name="new_password" required minlength="6" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    </div>
                    <div style="margin-bottom: 15px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 500;">Confirm New Password:</label>
                        <input type="password" name="confirm_password" required minlength="6" style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px;">
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button type="submit" style="background: #28a745; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">Update Password</button>
                        <button type="button" onclick="togglePasswordForm()" style="background: #6c757d; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer;">Cancel</button>
                    </div>
                </form>
            </div>
        </div>
        
        <div class="card">
            <h3>🔧 System Information</h3>
            <div class="setting-item">
                <div>
                    <div class="setting-label">Server Time</div>
                    <div class="setting-description">Current server timestamp</div>
                </div>
                <div class="setting-value">{{ server_time }}</div>
            </div>
            <div class="setting-item">
                <div>
                    <div class="setting-label">Security Mode</div>
                    <div class="setting-description">Authentication and security status</div>
                </div>
                <div class="setting-value" style="color: #28a745;">🛡️ Enabled</div>
            </div>
            <div class="setting-item">
                <div>
                    <div class="setting-label">Database</div>
                    <div class="setting-description">Data storage status</div>
                </div>
                <div class="setting-value" style="color: #28a745;">✅ Connected</div>
            </div>
        </div>

        <div class="card danger-zone">
            <h3>⚠️ Danger Zone</h3>
            <div class="setting-item">
                <div>
                    <div class="setting-label">Clear All GPS Data</div>
                    <div class="setting-description">Permanently delete all stored GPS coordinates</div>
                </div>
                <a href="{{ url_for('clear_data') }}" class="btn-danger" onclick="return confirm('Are you sure you want to delete ALL GPS data? This action cannot be undone!')">Clear All Data</a>
            </div>
        </div>
    </div>

    <script>
        function copyToClipboard(elementId) {
            const element = document.getElementById(elementId);
            element.select();
            element.setSelectionRange(0, 99999); // For mobile devices
            
            try {
                document.execCommand('copy');
                
                // Show feedback
                const btn = event.target;
                const originalText = btn.textContent;
                btn.textContent = 'Copied!';
                btn.style.background = '#28a745';
                
                setTimeout(() => {
                    btn.textContent = originalText;
                    btn.style.background = '#007bff';
                }, 1500);
            } catch (err) {
                console.error('Failed to copy: ', err);
                alert('Copy failed. Please manually select and copy the text.');
            }
        }
        
        function togglePasswordForm() {
            const form = document.getElementById('password-form');
            const toggle = document.getElementById('password-toggle');
            
            if (form.style.display === 'none' || form.style.display === '') {
                form.style.display = 'block';
                toggle.textContent = 'Cancel';
                toggle.style.background = '#dc3545';
            } else {
                form.style.display = 'none';
                toggle.textContent = 'Change Password';
                toggle.style.background = '#007bff';
                // Clear form
                form.querySelectorAll('input').forEach(input => input.value = '');
            }
        }
        
        function toggleBoatForm() {
            const form = document.getElementById('boat-form');
            const toggle = document.getElementById('boat-toggle');
            
            if (form.style.display === 'none' || form.style.display === '') {
                form.style.display = 'block';
                toggle.textContent = 'Cancel';
                toggle.style.background = '#dc3545';
            } else {
                form.style.display = 'none';
                toggle.textContent = 'Edit Boat Info';
                toggle.style.background = '#007bff';
            }
        }
    </script>
</body>
</html>
'''

# User Management Template
USERS_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - User Management</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: white; padding: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .nav-brand { font-size: 20px; font-weight: bold; color: #333; }
        .nav-menu { display: flex; gap: 20px; align-items: center; }
        .nav-menu a { color: #666; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav-menu a:hover, .nav-menu a.active { background: #f0f0f0; color: #333; }
        .nav-user { color: #666; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 6px; }
        .alert-error { background: #fee; border: 1px solid #fcc; color: #c33; }
        .alert-success { background: #efe; border: 1px solid #cfc; color: #3c3; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 500; }
        .form-group input, .form-group select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }
        button, .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }
        button:hover, .btn:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .users-table { width: 100%; border-collapse: collapse; }
        .users-table th, .users-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .users-table th { background: #f8f9fa; font-weight: 600; }
        .badge { padding: 4px 8px; border-radius: 12px; font-size: 12px; font-weight: 500; }
        .badge-admin { background: #dc3545; color: white; }
        .badge-user { background: #28a745; color: white; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">🛡️ GPS Tracker</div>
            <div class="nav-menu">
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('weather') }}">Weather</a>
                <a href="{{ url_for('boat_info') }}">Boat Info</a>
                <a href="{{ url_for('float_plan') }}">Float Plan</a>
                <a href="{{ url_for('users') }}" class="active">Users</a>
                <a href="{{ url_for('settings') }}">Settings</a>
                <span class="nav-user">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <h1>User Management</h1>
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'error' if category == 'error' else 'success' }}">
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <h2>Create New User</h2>
            <form method="POST" action="{{ url_for('create_user') }}">
                <div class="form-row">
                    <div class="form-group">
                        <label for="username">Username:</label>
                        <input type="text" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email">
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    <div class="form-group">
                        <label for="is_admin">Role:</label>
                        <select id="is_admin" name="is_admin">
                            <option value="0">Regular User</option>
                            <option value="1">Administrator</option>
                        </select>
                    </div>
                </div>
                <button type="submit">Create User</button>
            </form>
        </div>
        
        <div class="card">
            <h2>Existing Users</h2>
            <table class="users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Email</th>
                        <th>Role</th>
                        <th>Created</th>
                        <th>Last Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    {% for user in users %}
                    <tr>
                        <td>{{ user.username }}</td>
                        <td>{{ user.email or 'Not set' }}</td>
                        <td>
                            {% if user.is_admin %}
                                <span class="badge badge-admin">Admin</span>
                            {% else %}
                                <span class="badge badge-user">User</span>
                            {% endif %}
                        </td>
                        <td>{{ user.created_at[:10] if user.created_at }}</td>
                        <td>{{ user.last_login[:10] if user.last_login else 'Never' }}</td>
                        <td>
                            {% if user.id != current_user.id %}
                                <a href="{{ url_for('reset_user_password', user_id=user.id) }}" 
                                   class="btn" style="background: #ffc107; color: #000; margin-right: 5px;"
                                   onclick="return confirm('Reset password for {{ user.username }}? They will need to use the new password displayed on screen.')">Reset Password</a>
                                <a href="{{ url_for('delete_user', user_id=user.id) }}" 
                                   class="btn btn-danger"
                                   onclick="return confirm('Delete user {{ user.username }}?')">Delete</a>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
    </div>
</body>
</html>
'''

# Weather Page Template
WEATHER_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - Weather & Radar</title>
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: white; padding: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav-container { max-width: 1600px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .nav-brand { font-size: 20px; font-weight: bold; color: #333; }
        .nav-menu { display: flex; gap: 20px; align-items: center; }
        .nav-menu a { color: #666; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav-menu a:hover, .nav-menu a.active { background: #f0f0f0; color: #333; }
        .container { max-width: 1600px; margin: 0 auto; padding: 20px; }
        .weather-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .weather-main { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .weather-item { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }
        .weather-value { font-size: 2em; font-weight: bold; color: #007bff; }
        .weather-label { font-size: 14px; color: #666; margin-top: 5px; }
        #map { height: 600px; border-radius: 10px; }
        .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .alert { padding: 12px; margin-bottom: 20px; border-radius: 6px; background: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }
        h2 { margin-bottom: 15px; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">🛡️ GPS Tracker - Weather & Radar</div>
            <div class="nav-menu">
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('weather') }}" class="active">Weather</a>
                <a href="{{ url_for('boat_info') }}">Boat Info</a>
                <a href="{{ url_for('float_plan') }}">Float Plan</a>
                {% if current_user.is_admin %}
                <a href="{{ url_for('users') }}">Users</a>
                <a href="{{ url_for('settings') }}">Settings</a>
                {% endif %}
                <span style="color: #666; font-size: 14px;">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <h1>Weather & Radar</h1>
        
        {% if not weather_api_configured %}
        <div class="alert">
            ⚠️ OpenWeatherMap API key not configured. Weather data will not be available. Please set OPENWEATHER_API_KEY environment variable.
        </div>
        {% endif %}
        
        <div class="weather-grid">
            <div class="card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2>Current Weather</h2>
                    <button class="btn" onclick="refreshWeather()">🔄 Refresh</button>
                </div>
                
                {% if weather %}
                <div class="weather-main">
                    <div class="weather-item">
                        <div class="weather-value">{{ "%.1f"|format(weather.temperature) }}°F</div>
                        <div class="weather-label">Temperature</div>
                    </div>
                    <div class="weather-item">
                        <div class="weather-value">{{ weather.humidity }}%</div>
                        <div class="weather-label">Humidity</div>
                    </div>
                    <div class="weather-item">
                        <div class="weather-value">{{ "%.1f"|format(weather.wind_speed) }} mph</div>
                        <div class="weather-label">Wind Speed</div>
                    </div>
                    <div class="weather-item">
                        <div class="weather-value">{{ weather.wind_direction }}°</div>
                        <div class="weather-label">Wind Direction</div>
                    </div>
                    <div class="weather-item">
                        <div class="weather-value">{{ "%.2f"|format(weather.pressure * 0.02953) }} inHg</div>
                        <div class="weather-label">Pressure</div>
                    </div>
                    <div class="weather-item">
                        <div class="weather-value">{{ "%.1f"|format(weather.visibility) }} mi</div>
                        <div class="weather-label">Visibility</div>
                    </div>
                </div>
                <div style="text-align: center; padding: 15px; background: #e7f3ff; border-radius: 8px;">
                    <div style="font-size: 1.5em; font-weight: bold; color: #007bff;">{{ weather.weather_main }}</div>
                    <div style="color: #666; margin-top: 5px;">{{ weather.weather_description }}</div>
                    <div style="font-size: 12px; color: #999; margin-top: 10px;">Last updated: {{ weather.timestamp[:19] }}</div>
                </div>
                {% else %}
                <div style="text-align: center; padding: 40px; color: #666;">
                    <p>No weather data available</p>
                    <p style="font-size: 14px; margin-top: 10px;">Weather updates automatically every 15 minutes</p>
                </div>
                {% endif %}
            </div>
            
            <div class="card">
                <h2>Radar Map</h2>
                <div id="map"></div>
            </div>
        </div>
    </div>

    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <script>
        let map;
        let radarLayer;
        
        function initMap() {
            {% if location %}
            const lat = {{ location.latitude }};
            const lng = {{ location.longitude }};
            {% else %}
            const lat = 0;
            const lng = 0;
            {% endif %}
            
            map = L.map('map').setView([lat, lng], {% if location %}10{% else %}2{% endif %});
            
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '© OpenStreetMap contributors',
                maxZoom: 19
            }).addTo(map);
            
            {% if location %}
            L.marker([lat, lng]).addTo(map)
                .bindPopup('<b>Current Location</b><br>Lat: ' + lat + '<br>Lng: ' + lng)
                .openPopup();
            
            // Add RainViewer radar layer
            fetch('https://api.rainviewer.com/public/weather-maps.json')
                .then(response => response.json())
                .then(data => {
                    if (data.radar && data.radar.past && data.radar.past.length > 0) {
                        const latestRadar = data.radar.past[data.radar.past.length - 1];
                        radarLayer = L.tileLayer(
                            'https://tilecache.rainviewer.com' + latestRadar.path + '/256/{z}/{x}/{y}/2/1_1.png',
                            {
                                attribution: 'RainViewer',
                                opacity: 0.6,
                                maxZoom: 19
                            }
                        ).addTo(map);
                    }
                })
                .catch(err => console.error('Error loading radar:', err));
            {% endif %}
        }
        
        function refreshWeather() {
            fetch('/api/weather/refresh', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('✅ Weather data refreshed!');
                        location.reload();
                    } else {
                        alert('❌ ' + data.message);
                    }
                })
                .catch(e => alert('❌ Error refreshing weather'));
        }
        
        // Auto-refresh every 15 minutes
        setInterval(() => {
            fetch('/api/weather/refresh', { method: 'POST' });
        }, 900000);
        
        document.addEventListener('DOMContentLoaded', initMap);
    </script>
</body>
</html>
'''

# Boat Information Page Template
BOAT_INFO_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - Boat Information</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: white; padding: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .nav-brand { font-size: 20px; font-weight: bold; color: #333; }
        .nav-menu { display: flex; gap: 20px; align-items: center; }
        .nav-menu a { color: #666; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav-menu a:hover, .nav-menu a.active { background: #f0f0f0; color: #333; }
        .nav-user { color: #666; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .boat-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .info-item { padding: 15px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #007bff; }
        .info-label { font-size: 12px; color: #666; text-transform: uppercase; font-weight: 600; margin-bottom: 5px; }
        .info-value { font-size: 18px; color: #333; font-weight: 500; }
        .no-data { text-align: center; padding: 40px; color: #999; }
        .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        h1 { margin-bottom: 20px; }
        .updated-info { text-align: center; margin-top: 20px; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">⛵ GPS Tracker - Boat Info</div>
            <div class="nav-menu">
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('weather') }}">Weather</a>
                <a href="{{ url_for('boat_info') }}" class="active">Boat Info</a>
                <a href="{{ url_for('float_plan') }}">Float Plan</a>
                {% if current_user.is_admin %}
                <a href="{{ url_for('users') }}">Users</a>
                <a href="{{ url_for('settings') }}">Settings</a>
                {% endif %}
                <span class="nav-user">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <h1>Boat Information</h1>
        
        {% if boat %}
        <div class="card">
            {% if boat.boat_image_filename %}
            <div style="text-align: center; margin-bottom: 30px;">
                <img src="{{ url_for('boat_image', filename=boat.boat_image_filename) }}" alt="Boat image" style="max-width: 100%; max-height: 400px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.15);">
            </div>
            {% endif %}
            <div class="boat-grid">
                <div class="info-item">
                    <div class="info-label">Registration Number</div>
                    <div class="info-value">{{ boat.registration_number or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">BIN Number</div>
                    <div class="info-value">{{ boat.bin_number or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Model</div>
                    <div class="info-value">{{ boat.model or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Year</div>
                    <div class="info-value">{{ boat.year or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Color</div>
                    <div class="info-value">{{ boat.color or 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Length</div>
                    <div class="info-value">{{ '%.1f ft'|format(boat.length) if boat.length else 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Draft</div>
                    <div class="info-value">{{ '%.1f ft'|format(boat.draft) if boat.draft else 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Beam</div>
                    <div class="info-value">{{ '%.1f ft'|format(boat.beam) if boat.beam else 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Fuel Tank Size</div>
                    <div class="info-value">{{ '%.0f gal'|format(boat.fuel_tank_size) if boat.fuel_tank_size else 'N/A' }}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Engine Size</div>
                    <div class="info-value">{{ boat.engine_size or 'N/A' }}</div>
                </div>
                <div class="info-item" style="grid-column: span 2;">
                    <div class="info-label">Engine Serial Number</div>
                    <div class="info-value">{{ boat.engine_serial or 'N/A' }}</div>
                </div>
            </div>
            <div class="updated-info">
                Last updated: {{ boat.updated_at[:19] if boat.updated_at else 'Unknown' }}
            </div>
        </div>
        
        {% if current_user.is_admin %}
        <div style="text-align: center; margin-top: 20px;">
            <a href="{{ url_for('settings') }}" class="btn">Edit Boat Information</a>
        </div>
        {% endif %}
        
        {% else %}
        <div class="card">
            <div class="no-data">
                <h2>No boat information available</h2>
                <p style="margin-top: 10px;">{% if current_user.is_admin %}Add boat details in Settings{% else %}Contact an administrator to add boat information{% endif %}</p>
            </div>
        </div>
        
        {% if current_user.is_admin %}
        <div style="text-align: center; margin-top: 20px;">
            <a href="{{ url_for('settings') }}" class="btn">Add Boat Information</a>
        </div>
        {% endif %}
        {% endif %}
    </div>
</body>
</html>
'''

# Float Plan Page Template
FLOAT_PLAN_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GPS Tracker - Float Plan</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; }
        .navbar { background: white; padding: 15px 0; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .nav-container { max-width: 1400px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .nav-brand { font-size: 20px; font-weight: bold; color: #333; }
        .nav-menu { display: flex; gap: 20px; align-items: center; }
        .nav-menu a { color: #666; text-decoration: none; padding: 8px 12px; border-radius: 4px; }
        .nav-menu a:hover, .nav-menu a.active { background: #f0f0f0; color: #333; }
        .nav-user { color: #666; font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .card { background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 20px; }
        .btn { background: #007bff; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; text-decoration: none; display: inline-block; font-size: 14px; }
        .btn:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        h1 { margin-bottom: 20px; }
        .leg-card { background: #f8f9fa; padding: 20px; margin-bottom: 15px; border-radius: 8px; border-left: 4px solid #007bff; }
        .leg-header { font-size: 18px; font-weight: bold; color: #333; margin-bottom: 15px; display: flex; justify-content: space-between; align-items: center; }
        .leg-type { font-size: 12px; background: #007bff; color: white; padding: 4px 8px; border-radius: 4px; margin-left: 10px; }
        .leg-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; margin-bottom: 10px; }
        .leg-field { padding: 10px; background: white; border-radius: 5px; }
        .leg-label { font-size: 11px; color: #666; text-transform: uppercase; font-weight: 600; margin-bottom: 5px; }
        .leg-value { font-size: 14px; color: #333; }
        .form-group { margin-bottom: 15px; }
        .form-label { display: block; margin-bottom: 5px; font-weight: 600; font-size: 14px; color: #333; }
        .form-input, .form-textarea, .form-select { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; font-size: 14px; }
        .form-textarea { min-height: 100px; resize: vertical; }
        .form-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .button-group { display: flex; gap: 10px; margin-top: 15px; flex-wrap: wrap; }
        .no-plan { text-align: center; padding: 40px; color: #666; }
        #editForm { display: none; }
        .leg-item { border-bottom: 2px solid #e0e0e0; padding-bottom: 15px; margin-bottom: 15px; }
        .leg-item:last-child { border-bottom: none; }
        .btn-remove-leg { background: #dc3545; color: white; border: none; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
        .btn-remove-leg:hover { background: #c82333; }
        .coordinates-hint { font-size: 12px; color: #666; font-style: italic; margin-top: 5px; }
    </style>
</head>
<body>
    <nav class="navbar">
        <div class="nav-container">
            <div class="nav-brand">⛵ GPS Tracker - Float Plan</div>
            <div class="nav-menu">
                <a href="{{ url_for('dashboard') }}">Dashboard</a>
                <a href="{{ url_for('weather') }}">Weather</a>
                <a href="{{ url_for('boat_info') }}">Boat Info</a>
                <a href="{{ url_for('float_plan') }}" class="active">Float Plan</a>
                {% if current_user.is_admin %}
                <a href="{{ url_for('users') }}">Users</a>
                <a href="{{ url_for('settings') }}">Settings</a>
                {% endif %}
                <span class="nav-user">{{ current_user.username }}</span>
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </nav>

    <div class="container">
        <h1>Float Plan</h1>
        
        <!-- Display Mode -->
        <div id="displayMode">
            {% if legs %}
            <div class="card">
                <div class="button-group">
                    <button class="btn" onclick="showEditForm()">✏️ Edit Float Plan</button>
                    <button class="btn btn-danger" onclick="resetFloatPlan()">🗑️ Reset Float Plan</button>
                </div>
            </div>
            
            {% for leg in legs %}
            <div class="leg-card">
                <div class="leg-header">
                    <div>
                        {{ leg.location_name or 'Waypoint ' + (loop.index|string) }}
                        <span class="leg-type">{{ leg.location_type or 'waypoint' }}</span>
                    </div>
                </div>
                
                <div class="leg-row">
                    {% if leg.address %}
                    <div class="leg-field">
                        <div class="leg-label">Address</div>
                        <div class="leg-value">{{ leg.address }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.latitude and leg.longitude %}
                    <div class="leg-field">
                        <div class="leg-label">Coordinates</div>
                        <div class="leg-value">{{ '%.5f'|format(leg.latitude) }}, {{ '%.5f'|format(leg.longitude) }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.arrival_time %}
                    <div class="leg-field">
                        <div class="leg-label">Arrival Time</div>
                        <div class="leg-value">{{ leg.arrival_time }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.departure_time %}
                    <div class="leg-field">
                        <div class="leg-label">Departure Time</div>
                        <div class="leg-value">{{ leg.departure_time }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.phone %}
                    <div class="leg-field">
                        <div class="leg-label">Phone</div>
                        <div class="leg-value">{{ leg.phone }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.vhf_channel %}
                    <div class="leg-field">
                        <div class="leg-label">VHF Channel</div>
                        <div class="leg-value">{{ leg.vhf_channel }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.website %}
                    <div class="leg-field">
                        <div class="leg-label">Website</div>
                        <div class="leg-value"><a href="{{ leg.website }}" target="_blank">{{ leg.website }}</a></div>
                    </div>
                    {% endif %}
                    
                    {% if leg.travel_duration %}
                    <div class="leg-field">
                        <div class="leg-label">Travel Duration</div>
                        <div class="leg-value">{{ leg.travel_duration }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.speed_estimate %}
                    <div class="leg-field">
                        <div class="leg-label">Speed Estimate</div>
                        <div class="leg-value">{{ leg.speed_estimate }}</div>
                    </div>
                    {% endif %}
                    
                    {% if leg.fuel_consumption %}
                    <div class="leg-field">
                        <div class="leg-label">Fuel Consumption</div>
                        <div class="leg-value">{{ leg.fuel_consumption }}</div>
                    </div>
                    {% endif %}
                </div>
                
                {% if leg.notes %}
                <div style="margin-top: 15px;">
                    <div class="leg-label">Notes</div>
                    <div class="leg-value" style="white-space: pre-wrap;">{{ leg.notes }}</div>
                </div>
                {% endif %}
                
                {% if leg.approach_instructions %}
                <div style="margin-top: 15px;">
                    <div class="leg-label">Approach Instructions</div>
                    <div class="leg-value" style="white-space: pre-wrap;">{{ leg.approach_instructions }}</div>
                </div>
                {% endif %}
            </div>
            {% endfor %}
            
            {% else %}
            <div class="card">
                <div class="no-plan">
                    <h2>No float plan created</h2>
                    <p style="margin-top: 10px;">Create a float plan to track your journey waypoints</p>
                    <button class="btn" onclick="showEditForm()" style="margin-top: 20px;">➕ Create Float Plan</button>
                </div>
            </div>
            {% endif %}
        </div>
        
        <!-- Edit Mode -->
        <div id="editForm">
            <div class="card">
                <h2>Edit Float Plan</h2>
                <form id="floatPlanForm">
                    <div class="form-group">
                        <label class="form-label" for="title">Float Plan Title</label>
                        <input type="text" class="form-input" id="title" name="title" placeholder="e.g., Deltaville to Norfolk - Nov 6, 2024">
                    </div>
                    
                    <div id="legs"></div>
                    
                    <div class="button-group">
                        <button type="button" class="btn" onclick="addLeg()">➕ Add Leg/Waypoint</button>
                        <button type="submit" class="btn btn-success">💾 Save Float Plan</button>
                        <button type="button" class="btn btn-danger" onclick="cancelEdit()">❌ Cancel</button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        let legCount = 0;
        
        function addLeg(data = {}) {
            const legId = legCount++;
            const legHtml = `
                <div class="leg-item" id="leg-${legId}">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h3 style="margin: 0;">Leg ${legId + 1}</h3>
                        <button type="button" class="btn-remove-leg" onclick="removeLeg(${legId})">Remove</button>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Location Name *</label>
                            <input type="text" class="form-input" name="legs[${legId}][location_name]" value="${data.location_name || ''}" placeholder="e.g., Norview Marina" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Location Type</label>
                            <select class="form-select" name="legs[${legId}][location_type]">
                                <option value="departure" ${data.location_type === 'departure' ? 'selected' : ''}>Departure</option>
                                <option value="waypoint" ${data.location_type === 'waypoint' || !data.location_type ? 'selected' : ''}>Waypoint</option>
                                <option value="destination" ${data.location_type === 'destination' ? 'selected' : ''}>Destination</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Address</label>
                        <input type="text" class="form-input" name="legs[${legId}][address]" value="${data.address || ''}" placeholder="e.g., 18691 General Puller Hwy, Deltaville, VA 23043">
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Latitude (Decimal Degrees)</label>
                            <input type="text" class="form-input" name="legs[${legId}][latitude]" value="${data.latitude || ''}" placeholder="e.g., 37.26370">
                            <div class="coordinates-hint">Use decimal degrees format (e.g., 37.26370)</div>
                        </div>
                        <div class="form-group">
                            <label class="form-label">Longitude (Decimal Degrees)</label>
                            <input type="text" class="form-input" name="legs[${legId}][longitude]" value="${data.longitude || ''}" placeholder="e.g., -76.01505">
                            <div class="coordinates-hint">Use decimal degrees format (e.g., -76.01505)</div>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Arrival Time</label>
                            <input type="text" class="form-input" name="legs[${legId}][arrival_time]" value="${data.arrival_time || ''}" placeholder="e.g., Nov. 6th 11:15 AM">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Departure Time</label>
                            <input type="text" class="form-input" name="legs[${legId}][departure_time]" value="${data.departure_time || ''}" placeholder="e.g., Nov. 6th 12:30 PM">
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Phone</label>
                            <input type="text" class="form-input" name="legs[${legId}][phone]" value="${data.phone || ''}" placeholder="e.g., (540) 698-1274">
                        </div>
                        <div class="form-group">
                            <label class="form-label">VHF Channel</label>
                            <input type="text" class="form-input" name="legs[${legId}][vhf_channel]" value="${data.vhf_channel || ''}" placeholder="e.g., Ch. 16">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Website</label>
                            <input type="text" class="form-input" name="legs[${legId}][website]" value="${data.website || ''}" placeholder="e.g., https://marina.com">
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label class="form-label">Travel Duration</label>
                            <input type="text" class="form-input" name="legs[${legId}][travel_duration]" value="${data.travel_duration || ''}" placeholder="e.g., 1 hour 15 minutes">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Speed Estimate</label>
                            <input type="text" class="form-input" name="legs[${legId}][speed_estimate]" value="${data.speed_estimate || ''}" placeholder="e.g., 25-35 MPH, 2700-3500 RPM">
                        </div>
                        <div class="form-group">
                            <label class="form-label">Fuel Consumption</label>
                            <input type="text" class="form-input" name="legs[${legId}][fuel_consumption]" value="${data.fuel_consumption || ''}" placeholder="e.g., 14-16 gallons (27%)">
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Notes</label>
                        <textarea class="form-textarea" name="legs[${legId}][notes]" placeholder="Additional information about this location...">${data.notes || ''}</textarea>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Approach Instructions</label>
                        <textarea class="form-textarea" name="legs[${legId}][approach_instructions]" placeholder="Detailed approach instructions...">${data.approach_instructions || ''}</textarea>
                    </div>
                </div>
            `;
            document.getElementById('legs').insertAdjacentHTML('beforeend', legHtml);
        }
        
        function removeLeg(legId) {
            document.getElementById(`leg-${legId}`).remove();
        }
        
        function showEditForm() {
            document.getElementById('displayMode').style.display = 'none';
            document.getElementById('editForm').style.display = 'block';
            
            // Load existing data
            fetch('/api/float-plan')
                .then(r => r.json())
                .then(data => {
                    if (data.plan) {
                        document.getElementById('title').value = data.plan.title || '';
                    }
                    if (data.legs && data.legs.length > 0) {
                        legCount = 0;
                        document.getElementById('legs').innerHTML = '';
                        data.legs.forEach(leg => addLeg(leg));
                    } else {
                        addLeg(); // Add one empty leg by default
                    }
                });
        }
        
        function cancelEdit() {
            document.getElementById('displayMode').style.display = 'block';
            document.getElementById('editForm').style.display = 'none';
        }
        
        function resetFloatPlan() {
            if (!confirm('Are you sure you want to reset the float plan? This cannot be undone.')) {
                return;
            }
            
            fetch('/api/float-plan/reset', { method: 'POST' })
                .then(r => r.json())
                .then(data => {
                    if (data.success) {
                        alert('✅ Float plan reset successfully');
                        location.reload();
                    } else {
                        alert('❌ ' + data.message);
                    }
                })
                .catch(e => alert('❌ Error resetting float plan'));
        }
        
        document.getElementById('floatPlanForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const title = formData.get('title');
            const legs = [];
            
            // Parse form data into legs array
            const legData = {};
            for (let [key, value] of formData.entries()) {
                if (key.startsWith('legs[')) {
                    const match = key.match(/legs\[(\d+)\]\[([^\]]+)\]/);
                    if (match) {
                        const legId = match[1];
                        const field = match[2];
                        if (!legData[legId]) legData[legId] = {};
                        legData[legId][field] = value;
                    }
                }
            }
            
            // Convert to array
            for (let legId in legData) {
                legs.push(legData[legId]);
            }
            
            if (legs.length === 0) {
                alert('Please add at least one leg/waypoint');
                return;
            }
            
            fetch('/api/float-plan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ title, legs })
            })
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    alert('✅ Float plan saved successfully');
                    location.reload();
                } else {
                    alert('❌ ' + data.message);
                }
            })
            .catch(e => alert('❌ Error saving float plan'));
        });
    </script>
</body>
</html>
'''

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return redirect(url_for('login'))
        
        db = get_db()
        cursor = db.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = bool(user['is_admin'])
            
            # Update last login
            db.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                      (datetime.now().isoformat(), user['id']))
            db.commit()
            
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    # Check if this is first time setup
    db = get_db()
    cursor = db.execute('SELECT COUNT(*) as count FROM users')
    user_count = cursor.fetchone()['count']
    first_login = user_count == 1  # Only default admin exists
    
    return render_template_string(LOGIN_TEMPLATE, first_login=first_login)

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@require_login
def dashboard():
    db = get_db()
    
    # Get current user info
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    current_user = cursor.fetchone()
    
    # Get GPS coordinates
    cursor = db.execute('''
        SELECT id, latitude, longitude, timestamp, device_id, source_format, created_at 
        FROM gps_coordinates 
        ORDER BY created_at DESC 
        LIMIT 50
    ''')
    coordinates = [dict(row) for row in cursor.fetchall()]
    coordinates.reverse()
    
    # Get statistics
    cursor = db.execute('SELECT COUNT(*) as total FROM gps_coordinates')
    marker_count = cursor.fetchone()['total']
    
    cursor = db.execute('SELECT COUNT(DISTINCT device_id) as devices FROM gps_coordinates')
    unique_devices = cursor.fetchone()['devices']
    
    cursor = db.execute('SELECT COUNT(*) as users FROM users')
    user_count = cursor.fetchone()['users']
    
    recent_coordinates = coordinates[-10:]
    recent_coordinates.reverse()
    
    last_update = datetime.now().strftime("%H:%M:%S")
    
    return render_template_string(
        DASHBOARD_TEMPLATE,
        current_user=current_user,
        coordinates=recent_coordinates,
        coordinates_json=json.dumps(coordinates),
        marker_count=marker_count,
        unique_devices=unique_devices,
        user_count=user_count,
        last_update=last_update
    )

@app.route('/users')
@require_admin
def users():
    db = get_db()
    
    # Get current user info
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    current_user = cursor.fetchone()
    
    # Get all users
    cursor = db.execute('SELECT * FROM users ORDER BY created_at')
    users_list = cursor.fetchall()
    
    return render_template_string(USERS_TEMPLATE, current_user=current_user, users=users_list)

@app.route('/create_user', methods=['POST'])
@require_admin
def create_user():
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip()
    password = request.form.get('password', '')
    is_admin = bool(int(request.form.get('is_admin', 0)))
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('users'))
    
    # Validate username
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        flash('Username can only contain letters, numbers, and underscores', 'error')
        return redirect(url_for('users'))
    
    if len(username) < 3:
        flash('Username must be at least 3 characters long', 'error')
        return redirect(url_for('users'))
    
    # Validate password
    if len(password) < 6:
        flash('Password must be at least 6 characters long', 'error')
        return redirect(url_for('users'))
    
    db = get_db()
    
    # Check if username already exists
    cursor = db.execute('SELECT id FROM users WHERE username = ?', (username,))
    if cursor.fetchone():
        flash('Username already exists', 'error')
        return redirect(url_for('users'))
    
    # Check if email already exists (if provided)
    if email:
        cursor = db.execute('SELECT id FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            flash('Email already exists', 'error')
            return redirect(url_for('users'))
    
    try:
        password_hash = generate_password_hash(password)
        db.execute('''
            INSERT INTO users (username, email, password_hash, is_admin)
            VALUES (?, ?, ?, ?)
        ''', (username, email or None, password_hash, is_admin))
        db.commit()
        
        flash(f'User {username} created successfully', 'success')
    except Exception as e:
        flash('Error creating user', 'error')
        app.logger.error(f"Error creating user: {e}")
    
    return redirect(url_for('users'))

@app.route('/reset_user_password/<int:user_id>')
@require_admin
def reset_user_password(user_id):
    if user_id == session['user_id']:
        flash('Cannot reset your own password here. Use the Settings page instead.', 'error')
        return redirect(url_for('users'))
    
    db = get_db()
    cursor = db.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('users'))
    
    try:
        # Generate a new random password
        import secrets
        import string
        
        # Generate a readable password
        new_password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        password_hash = generate_password_hash(new_password)
        
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user_id))
        db.commit()
        
        flash(f'Password reset for user "{user["username"]}". New password: {new_password}', 'success')
        app.logger.info(f"Password reset by admin for user: {user['username']}")
        
    except Exception as e:
        flash('Error resetting password', 'error')
        app.logger.error(f"Password reset error for user {user['username']}: {e}")
    
    return redirect(url_for('users'))

@app.route('/delete_user/<int:user_id>')
@require_admin
def delete_user(user_id):
    if user_id == session['user_id']:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('users'))
    
    db = get_db()
    cursor = db.execute('SELECT username FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('users'))
    
    try:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))
        db.commit()
        flash(f'User {user["username"]} deleted successfully', 'success')
    except Exception as e:
        flash('Error deleting user', 'error')
        app.logger.error(f"Error deleting user: {e}")
    
    return redirect(url_for('users'))

@app.route('/change_password', methods=['POST'])
@require_login
def change_password():
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validation
    if not current_password or not new_password or not confirm_password:
        flash('All password fields are required', 'error')
        return redirect(url_for('settings'))
    
    if new_password != confirm_password:
        flash('New passwords do not match', 'error')
        return redirect(url_for('settings'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters long', 'error')
        return redirect(url_for('settings'))
    
    db = get_db()
    
    # Get current user
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    user = cursor.fetchone()
    
    if not user:
        flash('User not found', 'error')
        return redirect(url_for('login'))
    
    # Verify current password
    if not check_password_hash(user['password_hash'], current_password):
        flash('Current password is incorrect', 'error')
        return redirect(url_for('settings'))
    
    # Update password
    try:
        new_password_hash = generate_password_hash(new_password)
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', 
                  (new_password_hash, session['user_id']))
        db.commit()
        
        flash('Password updated successfully', 'success')
        app.logger.info(f"Password changed for user: {user['username']}")
        
    except Exception as e:
        flash('Error updating password', 'error')
        app.logger.error(f"Password change error for user {user['username']}: {e}")
    
    return redirect(url_for('settings'))

@app.route('/settings')
@require_login
def settings():
    db = get_db()
    
    # Get current user info
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    current_user = cursor.fetchone()
    
    # Initialize default values
    api_key = 'Access denied - Admin only'
    stats = {
        'gps_points': 0,
        'unique_devices': 0,
        'total_users': 0,
        'admin_users': 0
    }
    
    # Get admin-only data if user is admin
    if current_user['is_admin']:
        # Get system statistics
        cursor = db.execute('SELECT COUNT(*) as total FROM gps_coordinates')
        gps_points = cursor.fetchone()['total']
        
        cursor = db.execute('SELECT COUNT(DISTINCT device_id) as devices FROM gps_coordinates')
        unique_devices = cursor.fetchone()['devices']
        
        cursor = db.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']
        
        cursor = db.execute('SELECT COUNT(*) as admins FROM users WHERE is_admin = 1')
        admin_users = cursor.fetchone()['admins']
        
        # Get API key from environment
        api_key = os.environ.get('GPS_API_KEY', 'Not configured')
        
        stats = {
            'gps_points': gps_points,
            'unique_devices': unique_devices,
            'total_users': total_users,
            'admin_users': admin_users
        }
    
    server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Get boat information
    cursor = db.execute('SELECT * FROM boat_info ORDER BY updated_at DESC LIMIT 1')
    boat = cursor.fetchone()
    
    return render_template_string(
        SETTINGS_TEMPLATE,
        current_user=current_user,
        api_key=api_key,
        stats=stats,
        server_time=server_time,
        boat=boat
    )

@app.route('/weather')
@require_login
def weather():
    """Weather and radar page"""
    db = get_db()
    
    # Get current user info
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    current_user = cursor.fetchone()
    
    # Get latest GPS coordinates
    cursor = db.execute('''
        SELECT latitude, longitude, created_at 
        FROM gps_coordinates 
        ORDER BY created_at DESC 
        LIMIT 1
    ''')
    location = cursor.fetchone()
    
    # Get latest weather data
    cursor = db.execute('''
        SELECT * FROM weather_data 
        ORDER BY created_at DESC 
        LIMIT 1
    ''')
    weather_data = cursor.fetchone()
    
    return render_template_string(
        WEATHER_TEMPLATE,
        current_user=current_user,
        location=location,
        weather=weather_data,
        weather_api_configured=bool(WEATHER_API_KEY)
    )

@app.route('/boat-info')
@require_login
def boat_info():
    """Boat information display page"""
    db = get_db()
    
    # Get current user info
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    current_user = cursor.fetchone()
    
    # Get boat information
    cursor = db.execute('SELECT * FROM boat_info ORDER BY updated_at DESC LIMIT 1')
    boat = cursor.fetchone()
    
    return render_template_string(
        BOAT_INFO_TEMPLATE,
        current_user=current_user,
        boat=boat
    )

@app.route('/update_boat_info', methods=['POST'])
@require_admin
def update_boat_info():
    """Update boat information"""
    db = get_db()
    
    # Get form data
    registration_number = request.form.get('registration_number', '').strip()[:8]
    length = request.form.get('length_ft', '')
    draft = request.form.get('draft_ft', '')
    beam = request.form.get('beam_ft', '')
    fuel_tank_size = request.form.get('fuel_tank_size_gal', '')
    engine_size = request.form.get('engine_size_hp', '').strip()
    engine_serial = request.form.get('engine_serial_number', '').strip()
    bin_number = request.form.get('bin_number', '').strip()
    color = request.form.get('color', '').strip()
    model = request.form.get('model', '').strip()
    year = request.form.get('year', '')
    
    # Handle boat image upload
    boat_image_filename = None
    if 'boat_image' in request.files:
        file = request.files['boat_image']
        if file and file.filename and allowed_file(file.filename):
            # Get old boat info to delete old image
            cursor = db.execute('SELECT boat_image_filename FROM boat_info ORDER BY updated_at DESC LIMIT 1')
            old_boat = cursor.fetchone()
            if old_boat and old_boat['boat_image_filename']:
                old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], old_boat['boat_image_filename'])
                if os.path.exists(old_image_path):
                    try:
                        os.remove(old_image_path)
                    except Exception as e:
                        app.logger.warning(f"Could not delete old boat image: {e}")
            
            # Save new image with timestamp to avoid conflicts
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(file.filename)
            boat_image_filename = f"boat_{timestamp}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], boat_image_filename)
            file.save(file_path)
    
    try:
        # Get existing boat image if not uploading new one
        if boat_image_filename is None:
            cursor = db.execute('SELECT boat_image_filename FROM boat_info ORDER BY updated_at DESC LIMIT 1')
            old_boat = cursor.fetchone()
            if old_boat:
                boat_image_filename = old_boat['boat_image_filename']
        
        # Delete old boat info (only keep one record)
        db.execute('DELETE FROM boat_info')
        
        # Insert new boat info
        db.execute('''
            INSERT INTO boat_info 
            (registration_number, length, draft, beam, fuel_tank_size, engine_size, 
             engine_serial, bin_number, color, model, year, boat_image_filename, updated_at, updated_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            registration_number or None,
            float(length) if length else None,
            float(draft) if draft else None,
            float(beam) if beam else None,
            float(fuel_tank_size) if fuel_tank_size else None,
            engine_size or None,
            engine_serial or None,
            bin_number or None,
            color or None,
            model or None,
            int(year) if year else None,
            boat_image_filename,
            datetime.now().isoformat(),
            session['user_id']
        ))
        
        db.commit()
        flash('Boat information updated successfully', 'success')
        
    except Exception as e:
        flash('Error updating boat information', 'error')
        app.logger.error(f"Boat info update error: {e}")
    
    return redirect(url_for('settings'))

@app.route('/boat-image/<filename>')
@require_login
def boat_image(filename):
    """Serve boat image files"""
    from flask import send_from_directory
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/clear')
@require_admin
def clear_data():
    db = get_db()
    db.execute('DELETE FROM gps_coordinates')
    db.commit()
    flash('All GPS data cleared successfully', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/track/clear', methods=['POST'])
@require_login
def clear_track():
    """Clear current track (recent GPS points)"""
    db = get_db()
    db.execute('UPDATE gps_coordinates SET is_track_point = 0')
    db.commit()
    return jsonify({'success': True, 'message': 'Track cleared'})

@app.route('/api/track/save', methods=['POST'])
@require_login
def save_track():
    """Save current track to track history"""
    data = request.get_json()
    name = data.get('name', f'Track {datetime.now().strftime("%Y-%m-%d %H:%M")}')
    description = data.get('description', '')
    
    db = get_db()
    
    # Get current track points
    cursor = db.execute('''
        SELECT latitude, longitude, timestamp 
        FROM gps_coordinates 
        WHERE is_track_point = 1
        ORDER BY created_at ASC
    ''')
    points = cursor.fetchall()
    
    if not points:
        return jsonify({'success': False, 'message': 'No track points to save'}), 400
    
    # Create track record
    cursor = db.execute('''
        INSERT INTO track_history (name, description, created_by)
        VALUES (?, ?, ?)
    ''', (name, description, session['user_id']))
    track_id = cursor.lastrowid
    
    # Save track points
    for i, point in enumerate(points):
        db.execute('''
            INSERT INTO track_points (track_id, latitude, longitude, timestamp, sequence_order)
            VALUES (?, ?, ?, ?, ?)
        ''', (track_id, point['latitude'], point['longitude'], point['timestamp'], i))
    
    db.commit()
    
    return jsonify({
        'success': True, 
        'message': f'Track saved: {name}',
        'track_id': track_id,
        'points_saved': len(points)
    })

@app.route('/api/track/list', methods=['GET'])
@require_login
def list_tracks():
    """List saved tracks"""
    db = get_db()
    cursor = db.execute('''
        SELECT t.id, t.name, t.description, t.created_at, u.username,
               COUNT(tp.id) as point_count
        FROM track_history t
        LEFT JOIN users u ON t.created_by = u.id
        LEFT JOIN track_points tp ON t.id = tp.track_id
        GROUP BY t.id
        ORDER BY t.created_at DESC
    ''')
    tracks = [dict(row) for row in cursor.fetchall()]
    return jsonify({'tracks': tracks})

@app.route('/api/track/<int:track_id>', methods=['GET'])
@require_login
def get_track(track_id):
    """Get track points for a saved track"""
    db = get_db()
    cursor = db.execute('''
        SELECT latitude, longitude, timestamp
        FROM track_points
        WHERE track_id = ?
        ORDER BY sequence_order ASC
    ''', (track_id,))
    points = [dict(row) for row in cursor.fetchall()]
    return jsonify({'points': points})

@app.route('/api/track/<int:track_id>', methods=['DELETE'])
@require_login
def delete_track(track_id):
    """Delete a saved track"""
    db = get_db()
    
    # Check if user owns the track or is admin
    cursor = db.execute('SELECT created_by FROM track_history WHERE id = ?', (track_id,))
    track = cursor.fetchone()
    
    if not track:
        return jsonify({'success': False, 'message': 'Track not found'}), 404
    
    if track['created_by'] != session['user_id'] and not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    db.execute('DELETE FROM track_history WHERE id = ?', (track_id,))
    db.commit()
    
    return jsonify({'success': True, 'message': 'Track deleted'})

@app.route('/api/route/upload', methods=['POST'])
@require_login
def upload_route():
    """Upload GPX route file"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'No file selected'}), 400
    
    if not file.filename.lower().endswith('.gpx'):
        return jsonify({'success': False, 'message': 'File must be a GPX file'}), 400
    
    try:
        gpx_content = file.read()
        if len(gpx_content) > 5 * 1024 * 1024:  # 5MB limit
            return jsonify({'success': False, 'message': 'File too large (max 5MB)'}), 400
        
        routes, tracks = parse_gpx_file(gpx_content)
        
        if not routes and not tracks:
            return jsonify({'success': False, 'message': 'No valid routes or tracks found in GPX file'}), 400
        
        db = get_db()
        saved_routes = []
        
        # Save routes
        for route in routes:
            cursor = db.execute('''
                INSERT INTO gpx_routes (name, description, filename, uploaded_by)
                VALUES (?, ?, ?, ?)
            ''', (route['name'] or 'Unnamed Route', route['description'], 
                  secure_filename(file.filename), session['user_id']))
            route_id = cursor.lastrowid
            
            for i, wpt in enumerate(route['waypoints']):
                db.execute('''
                    INSERT INTO gpx_waypoints (route_id, name, latitude, longitude, sequence_order)
                    VALUES (?, ?, ?, ?, ?)
                ''', (route_id, wpt['name'], wpt['latitude'], wpt['longitude'], i))
            
            saved_routes.append({'id': route_id, 'name': route['name'], 'type': 'route'})
        
        # Save tracks as routes
        for track in tracks:
            cursor = db.execute('''
                INSERT INTO gpx_routes (name, description, filename, uploaded_by)
                VALUES (?, ?, ?, ?)
            ''', (track['name'] or 'Unnamed Track', track['description'],
                  secure_filename(file.filename), session['user_id']))
            route_id = cursor.lastrowid
            
            for i, pt in enumerate(track['points']):
                db.execute('''
                    INSERT INTO gpx_waypoints (route_id, name, latitude, longitude, sequence_order)
                    VALUES (?, ?, ?, ?, ?)
                ''', (route_id, '', pt['latitude'], pt['longitude'], i))
            
            saved_routes.append({'id': route_id, 'name': track['name'], 'type': 'track'})
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': f'Uploaded {len(saved_routes)} route(s)',
            'routes': saved_routes
        })
        
    except Exception as e:
        app.logger.error(f"Route upload error: {e}")
        return jsonify({'success': False, 'message': f'Error processing file: {str(e)}'}), 500

@app.route('/api/route/list', methods=['GET'])
@require_login
def list_routes():
    """List uploaded routes"""
    db = get_db()
    cursor = db.execute('''
        SELECT r.id, r.name, r.description, r.filename, r.uploaded_at, 
               r.visible, r.color, u.username,
               COUNT(w.id) as waypoint_count
        FROM gpx_routes r
        LEFT JOIN users u ON r.uploaded_by = u.id
        LEFT JOIN gpx_waypoints w ON r.id = w.route_id
        GROUP BY r.id
        ORDER BY r.uploaded_at DESC
    ''')
    routes = [dict(row) for row in cursor.fetchall()]
    return jsonify({'routes': routes})

@app.route('/api/route/<int:route_id>', methods=['GET'])
@require_login
def get_route(route_id):
    """Get waypoints for a route"""
    db = get_db()
    cursor = db.execute('''
        SELECT r.name, r.description, r.color, r.visible
        FROM gpx_routes r
        WHERE r.id = ?
    ''', (route_id,))
    route_info = cursor.fetchone()
    
    if not route_info:
        return jsonify({'success': False, 'message': 'Route not found'}), 404
    
    cursor = db.execute('''
        SELECT name, latitude, longitude
        FROM gpx_waypoints
        WHERE route_id = ?
        ORDER BY sequence_order ASC
    ''', (route_id,))
    waypoints = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({
        'route': dict(route_info),
        'waypoints': waypoints
    })

@app.route('/api/route/<int:route_id>', methods=['DELETE'])
@require_login
def delete_route(route_id):
    """Delete a route"""
    db = get_db()
    
    # Check if user owns the route or is admin
    cursor = db.execute('SELECT uploaded_by FROM gpx_routes WHERE id = ?', (route_id,))
    route = cursor.fetchone()
    
    if not route:
        return jsonify({'success': False, 'message': 'Route not found'}), 404
    
    if route['uploaded_by'] != session['user_id'] and not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    db.execute('DELETE FROM gpx_routes WHERE id = ?', (route_id,))
    db.commit()
    
    return jsonify({'success': True, 'message': 'Route deleted'})

@app.route('/api/route/<int:route_id>/toggle', methods=['POST'])
@require_login
def toggle_route_visibility(route_id):
    """Toggle route visibility"""
    db = get_db()
    cursor = db.execute('SELECT visible FROM gpx_routes WHERE id = ?', (route_id,))
    route = cursor.fetchone()
    
    if not route:
        return jsonify({'success': False, 'message': 'Route not found'}), 404
    
    new_visibility = not route['visible']
    db.execute('UPDATE gpx_routes SET visible = ? WHERE id = ?', (new_visibility, route_id))
    db.commit()
    
    return jsonify({'success': True, 'visible': new_visibility})

# API Routes (same as before, with API key authentication)
@app.route('/api/gps', methods=['POST'])
def api_gps_secure():
    """Secure GPS endpoint with authentication and validation"""
    client_ip = request.remote_addr
    
    # Rate limiting
    if not check_rate_limit(client_ip, limit=10, window=60):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    # API key validation
    if not validate_api_key():
        return jsonify({'error': 'Valid API key required in X-API-Key header'}), 401
    
    db = get_db()
    
    try:
        # Handle different content types
        if request.is_json:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            lat, lng = validate_coordinates(data.get('latitude'), data.get('longitude'))
            if lat is None or lng is None:
                return jsonify({'error': 'Invalid coordinates'}), 400
            
            device_id = sanitize_input(data.get('deviceId', 'unknown'), 50)
            source_format = 'json'
            raw_data_hash = hash_data(json.dumps(data, sort_keys=True))
            
        # Handle NMEA data
        elif request.content_type and 'text' in request.content_type:
            nmea_data = request.get_data(as_text=True)
            if not nmea_data:
                return jsonify({'error': 'No NMEA data provided'}), 400
            
            # Limit NMEA data size
            if len(nmea_data) > 1000:
                return jsonify({'error': 'NMEA data too large'}), 400
            
            lat, lng = None, None
            for line in nmea_data.strip().split('\n')[:10]:  # Max 10 lines
                line = line.strip()
                if line.startswith('$GP') or line.startswith('$GN'):
                    lat, lng = parse_nmea_gps(line)
                    if lat is not None and lng is not None:
                        break
            
            if lat is None or lng is None:
                return jsonify({'error': 'No valid GPS coordinates found in NMEA data'}), 400
            
            device_id = f'nmea_{hash_data(client_ip)[:8]}'
            source_format = 'nmea'
            raw_data_hash = hash_data(nmea_data)
            
        else:
            return jsonify({'error': 'Unsupported content type'}), 400
        
        # Store in database
        timestamp = datetime.now().isoformat()
        remote_ip_hash = hash_data(client_ip)
        
        cursor = db.execute('''
            INSERT INTO gps_coordinates 
            (latitude, longitude, timestamp, device_id, remote_ip_hash, source_format, raw_data_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (lat, lng, timestamp, device_id, remote_ip_hash, source_format, raw_data_hash))
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'GPS coordinates received',
            'id': cursor.lastrowid,
            'timestamp': timestamp
        })
        
    except Exception as e:
        app.logger.error(f"GPS API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/nmea', methods=['POST'])
def api_nmea_secure():
    """Secure NMEA endpoint"""
    return api_gps_secure()

@app.route('/api/bareboat', methods=['POST']) 
def api_bareboat_secure():
    """Secure Bareboat endpoint"""
    return api_gps_secure()

@app.route('/api/weather', methods=['GET'])
@require_login
def api_weather():
    """Get latest weather data"""
    try:
        db = get_db()
        
        # Get latest weather data
        cursor = db.execute('''
            SELECT * FROM weather_data 
            ORDER BY created_at DESC 
            LIMIT 1
        ''')
        
        weather = cursor.fetchone()
        
        if weather:
            return jsonify({
                'success': True,
                'data': {
                    'latitude': weather['latitude'],
                    'longitude': weather['longitude'],
                    'timestamp': weather['timestamp'],
                    'temperature': weather['temperature'],
                    'humidity': weather['humidity'],
                    'pressure': weather['pressure'],
                    'wind_speed': weather['wind_speed'],
                    'wind_direction': weather['wind_direction'],
                    'visibility': weather['visibility'],
                    'weather_main': weather['weather_main'],
                    'weather_description': weather['weather_description'],
                    'precipitation': weather['precipitation']
                }
            })
        else:
            return jsonify({'success': False, 'message': 'No weather data available'}), 404
    
    except Exception as e:
        app.logger.error(f"Weather API error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/weather/refresh', methods=['POST'])
@require_login
def api_weather_refresh():
    """Manually refresh weather data for current location"""
    try:
        db = get_db()
        
        # Get latest GPS coordinates
        cursor = db.execute('''
            SELECT latitude, longitude 
            FROM gps_coordinates 
            ORDER BY created_at DESC 
            LIMIT 1
        ''')
        
        result = cursor.fetchone()
        if not result:
            return jsonify({'success': False, 'message': 'No GPS coordinates available'}), 404
        
        lat, lng = result['latitude'], result['longitude']
        
        # Fetch and store weather data
        weather_info = fetch_weather_data(lat, lng)
        if weather_info:
            store_weather_data(lat, lng, weather_info)
            return jsonify({'success': True, 'message': 'Weather data updated'})
        else:
            return jsonify({'success': False, 'message': 'Failed to fetch weather data'}), 500
    
    except Exception as e:
        app.logger.error(f"Weather refresh error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/float-plan')
@require_login
def float_plan():
    """Float plan page"""
    db = get_db()
    
    # Get current user info
    cursor = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
    current_user = cursor.fetchone()
    
    # Get active float plan
    cursor = db.execute('SELECT * FROM float_plans ORDER BY updated_at DESC LIMIT 1')
    plan = cursor.fetchone()
    
    legs = []
    if plan:
        cursor = db.execute('''
            SELECT * FROM float_plan_legs 
            WHERE plan_id = ? 
            ORDER BY leg_order ASC
        ''', (plan['id'],))
        legs = [dict(row) for row in cursor.fetchall()]
    
    return render_template_string(
        FLOAT_PLAN_TEMPLATE,
        current_user=current_user,
        plan=plan,
        legs=legs
    )

@app.route('/api/float-plan', methods=['GET'])
@require_login
def get_float_plan():
    """Get the current float plan"""
    db = get_db()
    cursor = db.execute('SELECT * FROM float_plans ORDER BY updated_at DESC LIMIT 1')
    plan = cursor.fetchone()
    
    if not plan:
        return jsonify({'success': True, 'plan': None, 'legs': []})
    
    cursor = db.execute('''
        SELECT * FROM float_plan_legs 
        WHERE plan_id = ? 
        ORDER BY leg_order ASC
    ''', (plan['id'],))
    legs = [dict(row) for row in cursor.fetchall()]
    
    return jsonify({
        'success': True,
        'plan': dict(plan),
        'legs': legs
    })

@app.route('/api/float-plan', methods=['POST'])
@require_login
def save_float_plan():
    """Save or update float plan"""
    try:
        data = request.get_json()
        db = get_db()
        
        title = data.get('title', 'Float Plan')
        legs = data.get('legs', [])
        
        if not legs:
            return jsonify({'success': False, 'message': 'At least one leg is required'}), 400
        
        # Delete existing float plan
        db.execute('DELETE FROM float_plans')
        
        # Create new float plan
        cursor = db.execute('''
            INSERT INTO float_plans (title, created_by)
            VALUES (?, ?)
        ''', (title, session['user_id']))
        plan_id = cursor.lastrowid
        
        # Save legs
        for i, leg in enumerate(legs):
            # Validate coordinates if provided
            lat = leg.get('latitude')
            lon = leg.get('longitude')
            
            if lat is not None and lat != '':
                try:
                    lat = float(lat)
                    if not (-90 <= lat <= 90):
                        return jsonify({'success': False, 'message': f'Invalid latitude in leg {i+1}'}), 400
                except ValueError:
                    return jsonify({'success': False, 'message': f'Invalid latitude format in leg {i+1}'}), 400
            else:
                lat = None
            
            if lon is not None and lon != '':
                try:
                    lon = float(lon)
                    if not (-180 <= lon <= 180):
                        return jsonify({'success': False, 'message': f'Invalid longitude in leg {i+1}'}), 400
                except ValueError:
                    return jsonify({'success': False, 'message': f'Invalid longitude format in leg {i+1}'}), 400
            else:
                lon = None
            
            db.execute('''
                INSERT INTO float_plan_legs (
                    plan_id, leg_order, location_name, location_type, address,
                    latitude, longitude, arrival_time, departure_time,
                    phone, vhf_channel, website, notes,
                    approach_instructions, speed_estimate, fuel_consumption, travel_duration
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                plan_id, i,
                leg.get('location_name', ''),
                leg.get('location_type', 'waypoint'),
                leg.get('address', ''),
                lat, lon,
                leg.get('arrival_time', ''),
                leg.get('departure_time', ''),
                leg.get('phone', ''),
                leg.get('vhf_channel', ''),
                leg.get('website', ''),
                leg.get('notes', ''),
                leg.get('approach_instructions', ''),
                leg.get('speed_estimate', ''),
                leg.get('fuel_consumption', ''),
                leg.get('travel_duration', '')
            ))
        
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Float plan saved successfully',
            'plan_id': plan_id
        })
    
    except Exception as e:
        app.logger.error(f"Float plan save error: {str(e)}")
        return jsonify({'success': False, 'message': f'Error saving float plan: {str(e)}'}), 500

@app.route('/api/float-plan/reset', methods=['POST'])
@require_login
def reset_float_plan():
    """Reset/delete the current float plan"""
    try:
        db = get_db()
        db.execute('DELETE FROM float_plans')
        db.commit()
        
        return jsonify({
            'success': True,
            'message': 'Float plan reset successfully'
        })
    
    except Exception as e:
        app.logger.error(f"Float plan reset error: {str(e)}")
        return jsonify({'success': False, 'message': f'Error resetting float plan: {str(e)}'}), 500

@app.route('/api/health')
def api_health_secure():
    """Health check endpoint"""
    client_ip = request.remote_addr
    
    if not check_rate_limit(client_ip, limit=5, window=60):
        return jsonify({'error': 'Rate limit exceeded'}), 429
    
    try:
        db = get_db()
        cursor = db.execute('SELECT COUNT(*) as total FROM gps_coordinates')
        count = cursor.fetchone()['total']
        
        cursor = db.execute('SELECT COUNT(DISTINCT device_id) as devices FROM gps_coordinates')
        devices = cursor.fetchone()['devices']
        
        return jsonify({
            'status': 'healthy',
            'pointsStored': count,
            'uniqueDevices': devices,
            'serverTime': datetime.now().isoformat(),
            'securityMode': 'enabled',
            'authenticationEnabled': True
        })
    except Exception:
        return jsonify({'status': 'unhealthy'}), 500

if __name__ == '__main__':
    init_db()
    print("🛡️ Secure GPS Tracker with Authentication starting...")
    print("🔐 Check console output for default admin credentials")
    
    # Start weather update background thread
    if WEATHER_API_KEY:
        weather_thread = threading.Thread(target=update_weather_task, daemon=True)
        weather_thread.start()
        print("🌤️ Weather update task started (updates every 15 minutes)")
    else:
        print("⚠️ Weather API key not configured - weather updates disabled")
    
    app.run(host='127.0.0.1', port=5001, debug=False)
