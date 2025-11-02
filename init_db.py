#!/usr/bin/env python3
import sqlite3
import secrets
from werkzeug.security import generate_password_hash

# Database configuration
DATABASE = 'gps_tracker.db'

def init_database():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    
    # GPS coordinates table (should already exist)
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
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
    else:
        print(f"Database already has {user_count} users")
    
    db.commit()
    db.close()
    print("Database initialization complete!")

if __name__ == '__main__':
    init_database()