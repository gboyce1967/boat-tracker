# GPS Tracker Update - Map View Persistence
**Date:** October 27, 2025  
**Server:** boat-tracker.grayworkscrafts.com  
**Application:** gps-tracker-secure

## Summary
Added map view persistence feature to prevent the map from auto-centering on the latest GPS coordinate during automatic page refreshes.

## Changes Made

### 1. Modified `app.py`
**Location:** `/var/www/gps-tracker-secure/app.py`

#### JavaScript Changes (lines ~698-758):
- **Added `saveMapView()` function** - Saves current map center and zoom to browser localStorage
- **Modified `initMap()` function** - Now checks localStorage for saved view before auto-centering
- **Added map event listeners** - Saves view on `moveend` and `zoomend` events
- **Modified auto-refresh** - Saves map view before `window.location.reload()`

### 2. Feature Details

#### How It Works:
1. When user pans or zooms the map, the position and zoom level are saved to localStorage
2. On page refresh (manual or automatic 60-second refresh), the map checks for saved view
3. If saved view exists, it restores that view instead of auto-centering
4. If no saved view exists (first visit), it defaults to centering on latest GPS coordinate
5. The "📍 Center on Latest" button remains functional for manual centering

#### localStorage Data Structure:
```json
{
  "center": [latitude, longitude],
  "zoom": zoomLevel
}
```

#### Key localStorage:
- **Key:** `mapView`
- **Stored per:** Browser (persists across sessions)
- **Clear method:** Browser's localStorage.clear() or developer tools

## Installation Steps Performed

### 1. Download Current File
```bash
sshpass -p '50HmmTC7#' scp root@boat-tracker.grayworkscrafts.com:/var/www/gps-tracker-secure/app.py /home/gary/boat-tracker/app.py
```

### 2. Edit Local Copy
Modified the `initMap()` function and added `saveMapView()` function

### 3. Upload Modified File
```bash
sshpass -p '50HmmTC7#' scp /home/gary/boat-tracker/app.py root@boat-tracker.grayworkscrafts.com:/var/www/gps-tracker-secure/app.py.new
```

### 4. Deploy on Server
```bash
cd /var/www/gps-tracker-secure
cp app.py app.py.backup-$(date +%Y%m%d-%H%M%S)  # Create backup
mv app.py.new app.py                              # Install new version
systemctl restart gps-tracker-secure              # Restart service
```

## Backup Information

### Automatic Backup Created:
- **Location:** `/var/www/gps-tracker-secure/app.py.backup-20251027-175027`
- **Purpose:** Previous version before this update

### Local Copy:
- **Location:** `/home/gary/boat-tracker/app.py`
- **Status:** Updated with latest changes

## Testing

### Test Procedure:
1. Open https://boat-tracker.grayworkscrafts.com
2. Login with credentials
3. Navigate to dashboard
4. Pan/zoom the map to a specific location
5. Wait for 60-second auto-refresh OR click "🔄 Refresh" button
6. Verify map stays at your positioned view (doesn't jump to latest GPS point)
7. Click "📍 Center on Latest" to verify manual centering still works

### Expected Behavior:
- ✅ Map maintains user's view position during automatic refreshes
- ✅ Map maintains user's zoom level during automatic refreshes
- ✅ "Center on Latest" button manually centers on newest GPS coordinate
- ✅ First-time visitors see map centered on latest GPS coordinate
- ✅ View persists across browser sessions (stored in localStorage)

## Rollback Procedure

If issues occur:

```bash
ssh root@boat-tracker.grayworkscrafts.com
cd /var/www/gps-tracker-secure
systemctl stop gps-tracker-secure
cp app.py.backup-20251027-175027 app.py
systemctl start gps-tracker-secure
systemctl status gps-tracker-secure
```

## Documentation Updates

### Files Updated:
1. **README.md** - Updated GPS Tracking features section and Dashboard section
2. **CHANGELOG.md** - Added new version entry for 2025-10-27 with map persistence details
3. **UPDATE_NOTES_2025-10-27.md** - This document

### Documentation Location:
- Local: `/home/gary/boat-tracker/`
- Server: `/var/www/gps-tracker-secure/` (app.py only)

## Server Details

- **Server:** boat-tracker.grayworkscrafts.com
- **IP/Access:** SSH via FQDN
- **User:** root
- **Application Path:** `/var/www/gps-tracker-secure/`
- **Service Name:** gps-tracker-secure.service
- **Port:** 5001 (Gunicorn) → 443 (Nginx HTTPS)

## Service Status After Update

```
● gps-tracker-secure.service - Secure GPS Tracker Web Application
     Loaded: loaded (/etc/systemd/system/gps-tracker-secure.service; enabled)
     Active: active (running)
     Workers: 2 Gunicorn workers
     Status: Healthy
```

## Additional Notes

- No database changes required
- No configuration changes required
- No service file changes required
- Change is client-side only (JavaScript in HTML template)
- Backward compatible (works for users with and without saved views)
- No impact on API endpoints or GPS data collection

## Future Enhancements (Optional)

Potential improvements for consideration:
1. Add "Reset View" button to clear saved localStorage view
2. Add visual indicator when map is in "auto-center mode" vs "user-positioned mode"
3. Add user preference in Settings to toggle auto-center behavior
4. Add option to auto-center only on new device detection

---

**Update completed successfully on October 27, 2025**
