# Custom Fields Feature & Deployment Pipeline

## Date: 2026-03-28

## Custom Fields Feature

### What Changed
Added the ability to create freeform custom fields on the boat information edit page. Custom fields are stored as individual rows in a new `boat_custom_fields` table (proper relational design, not JSON in a TEXT column).

### Database
- New table: `boat_custom_fields` with columns: `id`, `field_name`, `field_value`, `field_order`, `updated_by`
- New index: `idx_custom_field_order` on `field_order`
- The old `custom_fields TEXT` column on `boat_info` is now unused (left in place to avoid breaking the existing production schema)
- Table is auto-created by `init_db()` on next restart — no manual migration needed

### Backend Changes (app.py)
- `init_db()`: Added `boat_custom_fields` table creation and index
- `settings()` route: Now queries `boat_custom_fields` and passes to template
- `boat_info()` route: Now queries `boat_custom_fields` and passes to template
- `update_boat_info()` route: Reads `custom_field_name` and `custom_field_value` form arrays, clears and re-inserts all custom fields on each save

### Frontend Changes (app.py templates)
- **Settings (boat edit form)**: Added "Custom Fields" section below Engine Serial Number with:
  - "+ Add Field" button that dynamically adds name/value input rows
  - ✕ remove button per row with confirmation
  - Pre-populates existing custom fields when editing
- **Boat Info (display page)**: Custom fields rendered in the same grid as built-in fields, with a teal left border to visually distinguish them
- **JavaScript**: Added `addCustomField()` and `removeCustomField()` functions

### Bug Fixes (same session)
- Fixed Python 3.12+ SyntaxWarning for invalid escape sequence `\[` in the Float Plan template's JS regex (line 2570). Double-escaped backslashes so Python properly interprets them.
- **init_db() not running under gunicorn**: Was only called in `__main__` block which gunicorn skips. Moved `init_db()` to run at module load time (after function definition) so `CREATE TABLE IF NOT EXISTS` always executes. This means new tables/indexes are auto-created on restart — no manual migration needed.
- **Boat info form losing values on save**: The Settings form `value` attributes referenced wrong DB column names (e.g. `boat['length_ft']` instead of `boat['length']`). Six fields were affected: length, draft, beam, fuel_tank_size, engine_size, engine_serial. They always rendered empty in the edit form, so saving overwrote real data with blanks.
- **"Error updating boat information" crash**: When a numeric DB field was `None`, Jinja rendered it as the literal string `"None"` in the form. The backend then tried `float('None')` which crashed. Fixed with:
  - Template: `is not none` checks so None renders as empty string
  - Backend: `safe_float()` / `safe_int()` helpers that gracefully handle empty, `'None'`, and invalid values

## Deployment Pipeline

### Overview
Production server (192.168.101.12) now uses a git-based deployment model:
- Code lives in GitHub at `https://github.com/gboyce1967/boat-tracker.git`
- Production server has the repo cloned to `/var/www/gps-tracker-secure/`
- `update.sh` script handles: git pull, DB backup, permission fix, service restart, health check

### How to Deploy
From local machine:
```bash
ssh root@192.168.101.12 '/var/www/gps-tracker-secure/update.sh'
```

Or SSH in and run it directly:
```bash
/var/www/gps-tracker-secure/update.sh
```

### What update.sh Does
1. Pre-flight checks (git installed, repo exists)
2. Stashes any local modifications on the server
3. Backs up the database (keeps last 10 backups)
4. Pulls latest from GitHub `main` branch
5. Updates pip dependencies if `requirements.txt` changed
6. Fixes file permissions for the `gps-tracker` service user
7. Restarts `gps-tracker-secure` systemd service
8. Runs a health check against `http://127.0.0.1:5001/api/health`

### Files Preserved on Production (git-ignored)
- `gps_tracker.db` — the live database
- `venv/` — Python virtual environment
- `static/boat_images/` — uploaded boat images
- `backups/` — database backups
- `/etc/gps-tracker/config.env` — environment secrets (separate from repo)

### Production Server Setup (one-time)
1. Installed git on the server
2. Backed up existing app.py and database
3. Cloned the GitHub repo into `/var/www/gps-tracker-secure/`
4. Restored the database and venv into the cloned repo
5. Set permissions for `gps-tracker` user
6. Restarted the service
