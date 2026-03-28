# ⛵ Boat Information Feature

## Overview

The Boat Information feature allows administrators to store and display comprehensive boat details, including a photo of the vessel. All logged-in users can view the boat information, but only administrators can edit it.

## Features

### Boat Specifications
- **Registration Number** - Official boat registration (max 8 characters)
- **BIN Number** - Boat Identification Number
- **Model** - Make and model of the vessel
- **Year** - Year of manufacture
- **Color** - Primary color of the boat

### Physical Dimensions
- **Length** - Overall length in feet
- **Draft** - Draft/depth in feet
- **Beam** - Width at widest point in feet

### Engine & Fuel
- **Engine Size** - Horsepower rating
- **Engine Serial Number** - Engine manufacturer serial number
- **Fuel Tank Size** - Capacity in gallons

### Boat Image
- **Upload boat photo** - Display a photo of your vessel
- **Supported formats**: JPG, JPEG, PNG, GIF, WEBP
- **Maximum file size**: 10MB
- **Display**: Full-width hero image on boat info page

## Accessing the Feature

### Viewing Boat Information
1. Log in to the GPS Tracker
2. Click **"Boat Info"** in the navigation menu
3. View all boat specifications and the boat image (if uploaded)

Available to: **All logged-in users**

### Editing Boat Information
1. Log in as an administrator
2. Go to **Settings** page
3. Click **"Edit Boat Info"** button
4. Fill in or update boat details
5. (Optional) Upload a new boat image
6. Click **"Save Boat Info"**

Available to: **Administrators only**

## Image Upload Guidelines

### Supported Formats
- JPEG/JPG
- PNG
- GIF
- WEBP

### Requirements
- Maximum file size: 10MB
- Images are automatically timestamped to prevent conflicts
- Previous images are automatically deleted when uploading a new one

### Best Practices
- Use high-quality photos for best display
- Landscape orientation works best
- Recommended minimum resolution: 1920x1080
- Images are displayed at max 400px height on the page

## Technical Details

### Database Schema
```sql
boat_info (
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
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_by INTEGER,
    FOREIGN KEY (updated_by) REFERENCES users(id)
)
```

### File Storage
- **Location**: `/var/www/gps-tracker-secure/static/boat_images/`
- **Permissions**: Owned by `gps-tracker` user
- **Naming**: `boat_YYYYMMDD_HHMMSS_originalname.ext`

### Routes
- `GET /boat-info` - Display boat information page
- `POST /update_boat_info` - Update boat information (admin only)
- `GET /boat-image/<filename>` - Serve boat images (login required)

## Security

### Access Control
- **View**: Requires user authentication
- **Edit**: Requires administrator privileges
- **Images**: Only accessible to logged-in users

### File Upload Security
- File type validation (whitelist approach)
- File size limits enforced
- Secure filename generation
- Old images automatically deleted on replacement

## Installation

The installer automatically creates the required directory:

```bash
mkdir -p /var/www/gps-tracker-secure/static/boat_images
chown gps-tracker:gps-tracker /var/www/gps-tracker-secure/static/boat_images
chmod 775 /var/www/gps-tracker-secure/static/boat_images
```

### Manual Database Migration
If upgrading from an older version:

```bash
sqlite3 /var/www/gps-tracker-secure/gps_tracker.db \
  "ALTER TABLE boat_info ADD COLUMN boat_image_filename TEXT;"
```

## Troubleshooting

### Image Upload Fails
**Problem**: Permission denied error when uploading

**Solution**:
```bash
sudo chown -R gps-tracker:gps-tracker /var/www/gps-tracker-secure/static/boat_images
sudo chmod 775 /var/www/gps-tracker-secure/static/boat_images
```

### Image Not Displaying
**Problem**: Image uploaded but not showing on page

**Solution**:
1. Verify image was saved: `ls -la /var/www/gps-tracker-secure/static/boat_images/`
2. Check database: `sqlite3 gps_tracker.db "SELECT boat_image_filename FROM boat_info;"`
3. Verify file permissions: Image files should be owned by `gps-tracker` user
4. Clear browser cache and refresh

### Upload Size Exceeded
**Problem**: File too large to upload

**Solution**: 
- Resize image before uploading (recommended max 5MB)
- Or increase `MAX_CONTENT_LENGTH` in `app.py` if needed

## Usage Tips

### For Administrators
- Keep boat information up-to-date for safety and documentation
- Upload a clear, recent photo of the vessel
- Include engine serial numbers for maintenance tracking
- Update fuel tank size for accurate range calculations

### For All Users
- Reference boat info page for vessel specifications
- Use during trip planning for dimension restrictions
- Quick access to registration numbers if needed

## Future Enhancements

Potential future additions:
- Multiple boat photos (gallery)
- Insurance information storage
- Maintenance records
- Equipment inventory
- Document uploads (registration, insurance docs)

---

**Feature Added**: October 30, 2025
**Status**: Production Ready ✅
