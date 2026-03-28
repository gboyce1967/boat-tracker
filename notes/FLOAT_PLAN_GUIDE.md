# 🗺️ Float Plan Feature Guide

## Overview

The Float Plan feature allows you to create detailed trip plans with multiple legs/waypoints. This is essential for maritime navigation and safety, providing a comprehensive record of your planned route with all necessary details for each stop.

## Features

### Trip Planning
- **Multiple Legs/Waypoints** - Add unlimited legs to your float plan
- **Location Types** - Categorize each leg as departure, waypoint, or destination
- **GPS Coordinates** - Store precise locations in decimal degree format
- **Time Management** - Track arrival and departure times for each location

### Navigation Details
- **Contact Information** - Store phone numbers and VHF channels for marinas/facilities
- **Speed & Fuel Estimates** - Calculate and record fuel consumption and speed for each leg
- **Travel Duration** - Document expected travel times between waypoints
- **Approach Instructions** - Detailed navigation notes for safe arrival at each location

### Data Management
- **Edit Capability** - Modify existing float plans as needed
- **Reset Function** - Clear entire float plan to start a new trip
- **Persistent Storage** - All data saved to SQLite database
- **User Access** - All logged-in users can view and manage float plans

## Using the Float Plan Page

### Accessing Float Plans
1. Log in to your GPS Tracker
2. Click **"Float Plan"** in the main navigation menu
3. You'll see either your existing float plan or a prompt to create one

### Creating a New Float Plan

1. Click **"Create Float Plan"** or **"Edit Float Plan"** button
2. Enter a **Float Plan Title** (e.g., "Deltaville to Norfolk - Nov 6, 2024")
3. Click **"Add Leg/Waypoint"** to add your first location

### Adding Leg/Waypoint Details

For each leg, you can enter:

#### Required Fields
- **Location Name*** - Marina, anchorage, or waypoint name (e.g., "Norview Marina")
- **Location Type** - Select from:
  - Departure (starting point)
  - Waypoint (intermediate stop)
  - Destination (final location)

#### Location Details
- **Address** - Full street address
- **Latitude** - In decimal degrees (e.g., 37.26370)
- **Longitude** - In decimal degrees (e.g., -76.01505)

#### Timing
- **Arrival Time** - Free text format (e.g., "Nov. 6th 11:15 AM")
- **Departure Time** - Free text format (e.g., "Nov. 6th 12:30 PM")

#### Contact Information
- **Phone** - Marina or facility phone number
- **VHF Channel** - Radio channel (e.g., "Ch. 16")
- **Website** - URL for more information

#### Navigation Data
- **Travel Duration** - Expected time to reach this leg (e.g., "1 hour 15 minutes")
- **Speed Estimate** - Speed and RPM ranges (e.g., "25-35 MPH, 2700-3500 RPM")
- **Fuel Consumption** - Gallons and percentage (e.g., "14-16 gallons (27%)")

#### Additional Information
- **Notes** - General information, costs, requirements, etc.
- **Approach Instructions** - Detailed navigation directions for safe arrival

### Managing Legs

- **Add More Legs** - Click "Add Leg/Waypoint" button to add additional stops
- **Remove Legs** - Click "Remove" button on any leg to delete it
- **Reorder** - Legs are numbered automatically in the order you add them

### Saving Your Float Plan

1. After entering all legs, click **"Save Float Plan"**
2. The page will reload and display your complete float plan
3. All data is automatically saved to the database

### Editing an Existing Float Plan

1. Click **"Edit Float Plan"** button
2. The form will load with your current float plan data
3. Make any changes to legs or add/remove legs as needed
4. Click **"Save Float Plan"** to update

### Resetting a Float Plan

To start fresh with a new trip:

1. Click **"Reset Float Plan"** button
2. Confirm the action (this cannot be undone)
3. The float plan will be completely cleared
4. Create a new float plan from scratch

## GPS Coordinate Formats

The Float Plan feature uses **decimal degrees** format for GPS coordinates.

### Format Examples
- **Latitude**: 37.26370 (positive = North, negative = South)
- **Longitude**: -76.01505 (positive = East, negative = West)

### Converting from DMS (Degrees, Minutes, Seconds)

If you have coordinates in DMS format, convert them:

**Example: 37° 15.820'N, 076° 00.903'W**

1. Latitude: 37 + (15.820 / 60) = 37.26367°
2. Longitude: -(76 + (0.903 / 60)) = -76.01505°

Note: Western longitudes are negative, Eastern are positive
Note: Southern latitudes are negative, Northern are positive

### Online Conversion Tools
- [FCC DMS-Decimal Converter](https://www.fcc.gov/media/radio/dms-decimal)
- [NOAA Coordinate Converter](https://www.ngs.noaa.gov/NCAT/)

## Example Float Plan

Here's a sample float plan based on a real trip:

### Trip Title
"Deltaville to Norfolk - November 6, 2024"

### Leg 1: Departure
- **Location**: Norview Marina
- **Type**: Departure
- **Address**: 18691 General Puller Hwy, Deltaville, VA 23043
- **Departure Time**: Nov. 6th 10:00 AM
- **Phone**: (540) 698-1274
- **Notes**: $50 for ramp use plus keeping truck and trailer for 3 days. Spoke to Doug.

### Leg 2: Fuel/Safety Check
- **Location**: Cape Charles Yacht Center
- **Type**: Waypoint
- **Coordinates**: 37.26367, -76.01505
- **Arrival**: Nov. 6th 11:15 AM
- **Departure**: Nov. 6th 12:30 PM
- **VHF**: Ch. 16
- **Travel Duration**: 1 hour 15 minutes
- **Speed**: 25-35 MPH (2700-3500 RPM)
- **Fuel**: 14-16 gallons (27%)
- **Approach**: Follow Cape Charles deep-water channel from the Chesapeake Bay...

### Leg 3: Destination
- **Location**: Morningstar Marinas/Little Creek
- **Type**: Destination
- **Address**: 8166 Shore Dr, Norfolk, VA 23518
- **Coordinates**: 36.92327, -76.18954
- **Arrival**: Nov. 6th 2:15 PM
- **Phone**: (757) 587-8000
- **VHF**: Ch. 66
- **Travel Duration**: 1 hour
- **Fuel**: 17-19 gallons (30%)

## Database Schema

Float plans are stored in two tables:

### float_plans
- `id` - Unique plan identifier
- `title` - Float plan title
- `created_at` - Creation timestamp
- `updated_at` - Last modification timestamp
- `created_by` - User ID who created the plan

### float_plan_legs
- `id` - Unique leg identifier
- `plan_id` - Reference to parent float plan
- `leg_order` - Order of this leg in the sequence
- `location_name` - Name of the location
- `location_type` - departure, waypoint, or destination
- `address` - Full street address
- `latitude` - Decimal degrees
- `longitude` - Decimal degrees
- `arrival_time` - Expected arrival time (text)
- `departure_time` - Expected departure time (text)
- `phone` - Contact phone number
- `vhf_channel` - Radio channel
- `website` - URL for more info
- `notes` - General notes
- `approach_instructions` - Navigation instructions
- `speed_estimate` - Speed and RPM info
- `fuel_consumption` - Fuel usage estimates
- `travel_duration` - Expected travel time

## API Endpoints

### Get Float Plan
```bash
GET /api/float-plan
```
Returns the current float plan with all legs.

### Save Float Plan
```bash
POST /api/float-plan
Content-Type: application/json

{
  "title": "Trip Title",
  "legs": [
    {
      "location_name": "Marina Name",
      "location_type": "departure",
      "latitude": 37.26370,
      "longitude": -76.01505,
      ...
    }
  ]
}
```

### Reset Float Plan
```bash
POST /api/float-plan/reset
```
Deletes the current float plan.

## Best Practices

1. **Update Regularly** - Modify your float plan if your route or schedule changes
2. **Be Detailed** - Include as much information as possible for safety
3. **Share Your Plan** - Let someone on shore know your float plan details
4. **Include Contacts** - Always add marina phone numbers and VHF channels
5. **Check Weather** - Use the Weather page to verify conditions along your route
6. **Backup** - Consider taking screenshots or printing your float plan

## Troubleshooting

### Coordinates Not Displaying
- Ensure you're using decimal degree format (e.g., 37.26370, not 37° 15' 48")
- Check that latitude is between -90 and 90
- Check that longitude is between -180 and 180

### Save Not Working
- Ensure at least one leg has a location name
- Check browser console for error messages
- Verify you're logged in

### Lost Float Plan
- Float plans are stored in the database
- Check if someone else reset it
- Restore from backup if available

## Support

For issues with the Float Plan feature:
1. Check this guide for common solutions
2. Review the troubleshooting section
3. Check application logs: `sudo journalctl -u gps-tracker-secure -f`
4. Verify database connectivity

---

**Happy and safe cruising! ⛵**
