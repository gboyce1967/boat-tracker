# Weather & Radar Feature Setup

## Overview
The GPS Tracker now includes a weather and radar page that displays current weather conditions and live radar overlays based on your GPS coordinates. Weather data updates automatically every 15 minutes.

## Features
- **Live Weather Data**: Temperature (°F), humidity, pressure (inHg), wind speed (mph), visibility (mi)
- **Weather Radar**: Real-time radar overlay using RainViewer API
- **Imperial Units**: All weather data in US customary units
- **Auto-refresh**: Weather data updates every 15 minutes automatically
- **Manual Refresh**: Refresh button to update weather on-demand
- **Location-based**: Weather is fetched for your latest GPS coordinates

## Setup Instructions

### 1. Get an OpenWeatherMap API Key

1. Go to [https://openweathermap.org/api](https://openweathermap.org/api)
2. Sign up for a free account
3. Navigate to "API keys" in your account
4. Copy your API key (it looks like: `abc123def456ghi789jkl012mno345pq`)

**Note**: The free tier allows 1,000 API calls per day, which is more than enough for 15-minute updates.

### 2. Configure the API Key on the Server

SSH into your boat-tracker server:

```bash
ssh root@boat-tracker.grayworkscrafts.com
```

Edit the configuration file:

```bash
nano /etc/gps-tracker/config.env
```

Add the following line:

```
OPENWEATHER_API_KEY=your_api_key_here
```

Replace `your_api_key_here` with your actual OpenWeatherMap API key.

### 3. Reload and Restart the Service

```bash
systemctl restart gps-tracker-secure
```

### 4. Verify Setup

Check the service logs to confirm the weather update task started:

```bash
journalctl -u gps-tracker-secure -f
```

You should see: `🌤️ Weather update task started (updates every 15 minutes)`

## Usage

### Accessing the Weather Page

1. Log in to your GPS Tracker at [https://boat-tracker.grayworkscrafts.com](https://boat-tracker.grayworkscrafts.com)
2. Click on **"Weather"** in the navigation menu
3. View current weather conditions and radar overlay

### Understanding the Display

**Weather Panel:**
- Temperature (°F)
- Humidity (%)
- Wind Speed (mph) and Direction (°)
- Atmospheric Pressure (inHg)
- Visibility (mi)
- Weather condition and description

**Radar Map:**
- Shows your current location
- Displays live precipitation radar overlay
- Uses RainViewer API (no API key required)
- Green/yellow/red indicates light/moderate/heavy precipitation

### Manual Refresh

Click the **"🔄 Refresh"** button to manually update weather data without waiting for the automatic 15-minute interval.

## Troubleshooting

### Weather Data Not Showing

If weather data is not displaying:

1. **Check API Key Configuration**:
   ```bash
   ssh root@boat-tracker.grayworkscrafts.com
   grep OPENWEATHER_API_KEY /etc/gps-tracker/config.env
   ```

2. **Check Service Logs**:
   ```bash
   journalctl -u gps-tracker-secure -f
   ```
   Look for errors related to weather API calls

3. **Verify GPS Coordinates**:
   - Weather requires at least one GPS coordinate to be stored
   - Check the Dashboard to ensure GPS data is being received

4. **Test API Key Manually**:
   ```bash
   curl "https://api.openweathermap.org/data/2.5/weather?lat=40.7128&lon=-74.0060&appid=YOUR_API_KEY&units=metric"
   ```
   Replace `YOUR_API_KEY` with your actual key

### No GPS Coordinates Available

The weather page shows "No GPS coordinates available" if:
- No GPS data has been submitted yet
- Check the Dashboard to view GPS coordinates
- Submit test GPS data using the API

### Radar Not Loading

If the radar overlay doesn't appear:
- Check your internet connection
- RainViewer API might be temporarily unavailable
- Try refreshing the page

## API Endpoints

The weather feature adds these new API endpoints:

### Get Latest Weather Data
```bash
GET /api/weather
```
Returns the most recent weather data stored in the database.

### Manually Refresh Weather
```bash
POST /api/weather/refresh
```
Fetches fresh weather data for the current GPS location.

## Database Schema

Weather data is stored in the `weather_data` table:

```sql
CREATE TABLE weather_data (
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
);
```

## Security Notes

- The weather API endpoint requires authentication (login)
- API key is stored securely as an environment variable
- Weather data is only fetched based on your own GPS coordinates
- No external parties can access your weather or location data

## Future Enhancements

Potential improvements for future versions:
- Weather forecasts (3-day, 7-day)
- Weather alerts and warnings
- Historical weather data graphs
- Wave and tide information (for marine use)
- Multiple location weather tracking

## Support

For issues or questions:
1. Check service logs: `journalctl -u gps-tracker-secure -f`
2. Verify database: `sqlite3 /var/www/gps-tracker-secure/gps_tracker.db "SELECT * FROM weather_data LIMIT 1;"`
3. Review this documentation

---

**Weather & Radar Feature** - Added to GPS Tracker v2.1
