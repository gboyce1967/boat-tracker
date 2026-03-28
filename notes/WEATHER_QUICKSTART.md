# Weather Feature - Quick Start Guide

## ✅ What's Been Deployed

The GPS Tracker at boat-tracker.grayworkscrafts.com now has a **Weather & Radar** page! 

The update has been deployed and the service is running.

## 🌤️ What You Get

1. **Weather Page** - New "Weather" link in the navigation menu
2. **Live Weather Data** - Temperature (°F), humidity, wind (mph), pressure (inHg), visibility (mi)
3. **Imperial Units** - All weather in US customary units
4. **Radar Overlay** - Real-time precipitation radar on an interactive map
5. **Auto-Updates** - Weather refreshes every 15 minutes automatically
6. **Manual Refresh** - Click the refresh button to update on-demand

## ⚡ Quick Setup (5 minutes)

### Step 1: Get a Free API Key

1. Visit: https://openweathermap.org/api
2. Click "Sign Up" and create a free account
3. Go to your account dashboard → "API keys"
4. Copy your API key

### Step 2: Configure the Server

```bash
ssh root@boat-tracker.grayworkscrafts.com
```

Password: `50HmmTC7#`

```bash
# Edit the configuration file
nano /etc/gps-tracker/config.env
```

Add this line:

```
OPENWEATHER_API_KEY=paste_your_api_key_here
```

Save and exit (Ctrl+X, then Y, then Enter)

```bash
# Apply changes
systemctl restart gps-tracker-secure
```

### Step 3: Test It

1. Go to https://boat-tracker.grayworkscrafts.com
2. Log in
3. Click "Weather" in the navigation menu
4. You should see weather data and a radar map

## 📍 How It Works

- Weather is based on your **latest GPS coordinates**
- Updates automatically **every 15 minutes**
- Radar shows **live precipitation data** from RainViewer
- All data is stored locally in the database
- Requires at least one GPS coordinate to be available

## 🔧 If Weather Data Isn't Showing

1. **Check the API key is configured:**
   ```bash
   ssh root@boat-tracker.grayworkscrafts.com
   grep OPENWEATHER_API_KEY /etc/gps-tracker/config.env
   ```

2. **Verify GPS coordinates exist:**
   - Go to the Dashboard
   - Make sure you have at least one GPS point stored
   
3. **Check service logs:**
   ```bash
   ssh root@boat-tracker.grayworkscrafts.com
   journalctl -u gps-tracker-secure -f
   ```

4. **Wait for the first update:**
   - If you just configured the API key, wait up to 15 minutes for the first weather update
   - Or click the "Refresh" button on the Weather page to fetch immediately

## 📊 Technical Details

- **API**: OpenWeatherMap (free tier = 1,000 calls/day)
- **Units**: Imperial (Fahrenheit, mph, inHg, miles)
- **Update Frequency**: Every 15 minutes (96 calls/day)
- **Radar**: RainViewer API (no key required)
- **Database**: New `weather_data` table in SQLite
- **Background Task**: Cron job runs every 15 minutes

## 📝 Files Modified

- `app.py` - Added weather functionality, database tables, routes, and UI
- Deployed to `/var/www/gps-tracker-secure/app.py` on the server
- Backup created: `/var/www/gps-tracker-secure/app.py.backup-[timestamp]`
- Service: `gps-tracker-secure.service`

## 🎯 Next Steps

1. Configure the OpenWeatherMap API key (see Step 2 above)
2. Make sure GPS data is being received
3. Visit the Weather page and enjoy real-time weather and radar!

## 📚 Full Documentation

See `WEATHER_SETUP.md` for complete documentation including:
- Detailed setup instructions
- Troubleshooting guide
- API endpoint documentation
- Database schema
- Security notes

---

**Created**: October 30, 2025
**Version**: GPS Tracker v2.1 with Weather & Radar
