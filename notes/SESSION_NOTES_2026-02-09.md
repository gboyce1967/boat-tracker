# Boat Tracker Project Reorganization Notes
Date: 2026-02-09

## What Was Done
Reorganized the boat tracker project files from scattered locations in ~/home into proper project structure under ~/Projects/.

## Project Structure Created

### boat-tracker-web/
- Fresh git clone from https://github.com/gboyce1967/boat-tracker.git
- Contains the web-based GPS tracking application
- `notes/` folder contains:
  - All previous .md documentation files
  - gps_tracker.db.backup (database backup from previous install)

### boat-tracker-bareboat/
- SignalK GPS Tracker integration for OpenPlotter/OpenCPN/Bareboat Necessities
- Contains:
  - signalk-bridge.js - Bridge between SignalK and GPS tracker
  - signalk-gps-tracker-plugin/ - SignalK plugin
  - bareboat_endpoint.py - Bareboat Necessities API endpoint
  - Service files for systemd
  - Installation guides

## Files Cleaned Up From Home Directory
- boat-tracker/ (old working directory)
- boat-tracker_installer/ (installer with git)
- boat-tracker-installer.tar.gz
- gps_tracker.db
- Various loose .py files (app.py, init_db.py, debug_auth.py, etc.)
- api.php, config.php

## Git Repository
- Web app repo: https://github.com/gboyce1967/boat-tracker.git
- Currently on main branch, tracking origin/main
