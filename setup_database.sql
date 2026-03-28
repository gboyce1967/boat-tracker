-- Create database
CREATE DATABASE IF NOT EXISTS gps_tracker;
USE gps_tracker;

-- Create GPS coordinates table
CREATE TABLE IF NOT EXISTS gps_coordinates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    latitude DECIMAL(10, 8) NOT NULL,
    longitude DECIMAL(11, 8) NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    device_id VARCHAR(100) DEFAULT 'unknown',
    remote_ip VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_device_id (device_id),
    INDEX idx_created_at (created_at)
);

-- Optional: Create a user for the application (replace with your preferred credentials)
-- CREATE USER 'gps_user'@'localhost' IDENTIFIED BY 'secure_password_here';
-- GRANT SELECT, INSERT, UPDATE, DELETE ON gps_tracker.* TO 'gps_user'@'localhost';
-- FLUSH PRIVILEGES;