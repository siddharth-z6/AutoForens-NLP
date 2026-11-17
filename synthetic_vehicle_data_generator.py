"""
Synthetic Connected Vehicle & IVI Data Generator
Simulates multi-source forensic evidence dumps for connected vehicle incident investigations:
1. OEM Cloud Telematics Stream (JSON)
2. IVI Database Sync (SQLite) - Android Automotive / QNX mirror
3. Raw OEM Cloud Gateway Syslog (Unstructured Text)
"""

import json
import sqlite3
import os
from datetime import datetime, timedelta

def generate_evidence_environment(output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    base_time = datetime(2026, 11, 14, 23, 45, 0)
    vin = "1G1YY22U965104928"
    paired_phone = "+1-415-555-0199"

    # 1. Generate OEM Cloud Telematics Stream (JSON)
    telematics_data = {
        "metadata": {
            "oem_cloud_provider": "AutoCloud Connected Fleet Services",
            "account_id": "ACC-90421-US",
            "vehicle_identification_number": vin,
            "firmware_version": "v2026.44.2.1",
            "export_timestamp": (base_time + timedelta(minutes=10)).isoformat() + "Z"
        },
        "telemetry_records": []
    }

    # Simulate 60 seconds of driving with an incident at second 35
    for sec in range(60):
        t = base_time + timedelta(seconds=sec)
        t_iso = t.isoformat() + "Z"
        
        # Scenario progression
        if sec < 25:
            speed = 65.0 + (sec % 3) * 0.5
            brake = 0.0
            throttle = 28.0
            steering = 0.5
            event = "NORMAL_CRUISE"
        elif 25 <= sec < 32:
            # Distraction phase: drifting slightly, throttle fluctuating
            speed = 67.5 + (sec % 2) * 1.2
            brake = 0.0
            throttle = 34.0
            steering = -4.2  # lane departure drift
            event = "LANE_DEPARTURE_WARNING"
        elif 32 <= sec < 35:
            # Panic reaction
            speed = 58.0 - (sec - 32) * 12.0
            brake = 85.0
            throttle = 0.0
            steering = 18.5  # aggressive evasive counter-steer
            event = "EMERGENCY_BRAKE_ACTUATION"
        elif sec == 35:
            # Collision event
            speed = 18.0
            brake = 100.0
            throttle = 0.0
            steering = 2.0
            event = "AIRBAG_DEPLOYMENT_PRIMARY_IMPACT"
        else:
            # Post-collision stationary
            speed = 0.0
            brake = 0.0
            throttle = 0.0
            steering = 0.0
            event = "VEHICLE_DISABLED_POST_IMPACT"

        record = {
            "timestamp": t_iso,
            "vin": vin,
            "gps": {
                "latitude": 37.7749 + (sec * 0.00015),
                "longitude": -122.4194 + (sec * 0.00012),
                "heading": 42.1,
                "altitude_m": 16.4
            },
            "dynamics": {
                "speed_kph": round(speed * 1.60934, 2),
                "speed_mph": round(speed, 1),
                "brake_pedal_pct": brake,
                "throttle_pct": throttle,
                "steering_angle_deg": steering,
                "seatbelt_driver_buckled": True,
                "gear_position": "D" if sec < 36 else "P"
            },
            "dtc_faults": ["B0001-13"] if sec >= 35 else [],
            "event_tag": event
        }
        telematics_data["telemetry_records"].append(record)

    telematics_path = os.path.join(output_dir, "cloud_telematics_stream.json")
    with open(telematics_path, "w", encoding="utf-8") as f:
        json.dump(telematics_data, f, indent=2)

    # 2. Generate In-Vehicle Infotainment (IVI) SQLite Database Sync
    ivi_db_path = os.path.join(output_dir, "ivi_companion_sync.sqlite")
    if os.path.exists(ivi_db_path):
        os.remove(ivi_db_path)

    conn = sqlite3.connect(ivi_db_path)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE bluetooth_paired_devices (
            device_id INTEGER PRIMARY KEY,
            mac_address TEXT,
            device_name TEXT,
            paired_timestamp TEXT,
            connection_status TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE sms_messages_sync (
            message_id INTEGER PRIMARY KEY,
            phone_number TEXT,
            sender_name TEXT,
            message_direction TEXT,
            timestamp_utc TEXT,
            message_body TEXT,
            read_status INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE voice_assistant_logs (
            interaction_id INTEGER PRIMARY KEY,
            timestamp_utc TEXT,
            recognized_transcript TEXT,
            intent_detected TEXT,
            response_code INTEGER
        )
    """)
    cur.execute("""
        CREATE TABLE call_logs (
            call_id INTEGER PRIMARY KEY,
            phone_number TEXT,
            contact_name TEXT,
            call_type TEXT,
            timestamp_utc TEXT,
            duration_seconds INTEGER
        )
    """)

    # Populate IVI DB
    cur.execute("""
        INSERT INTO bluetooth_paired_devices VALUES 
        (1, 'DC:E5:5B:22:90:AF', "User's iPhone 16 Pro", '2026-11-14T23:30:15Z', 'CONNECTED')
    """)

    # Interactions around the incident (Base time 23:45:00, incident at 23:45:35)
    cur.executemany("""
        INSERT INTO sms_messages_sync VALUES (?, ?, ?, ?, ?, ?, ?)
    """, [
        (1, paired_phone, "Sarah Miller", "INCOMING", (base_time + timedelta(seconds=12)).isoformat() + "Z", 
         "Where are you guys? The dinner reservation is at midnight.", 1),
        (2, paired_phone, "Sarah Miller", "INCOMING", (base_time + timedelta(seconds=24)).isoformat() + "Z", 
         "Urgent: Check your email right now, the deal contract arrived!", 1),
        (3, paired_phone, "Sarah Miller", "OUTGOING", (base_time + timedelta(seconds=29)).isoformat() + "Z", 
         "Opening it now on my screen", 1)
    ])

    cur.executemany("""
        INSERT INTO voice_assistant_logs VALUES (?, ?, ?, ?, ?)
    """, [
        (1, (base_time + timedelta(seconds=5)).isoformat() + "Z", 
         "Navigate to 742 Evergreen Terrace", "NAV_SET_DESTINATION", 200),
        (2, (base_time + timedelta(seconds=27)).isoformat() + "Z", 
         "Read the last incoming message from Sarah", "SMS_READ_REQUEST", 200),
        (3, (base_time + timedelta(seconds=36)).isoformat() + "Z", 
         "Emergency eCall automated dispatch initiated", "ECALL_AUTO_DISPATCH", 101)
    ])

    cur.executemany("""
        INSERT INTO call_logs VALUES (?, ?, ?, ?, ?, ?)
    """, [
        (1, "+1-415-555-0100", "Work HQ", "MISSED", (base_time + timedelta(minutes=-15)).isoformat() + "Z", 0),
        (2, "911", "Emergency Services", "OUTGOING", (base_time + timedelta(seconds=40)).isoformat() + "Z", 85)
    ])

    conn.commit()
    conn.close()

    # 3. Generate Raw OEM Cloud Gateway Syslog (Unstructured Text)
    syslog_path = os.path.join(output_dir, "raw_cloud_gateway.log")
    syslog_lines = [
        f"{base_time.strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: INFO [TCU-UPLINK] Handshake authenticated for VIN={vin} via eSIM IMSI=310410928301928",
        f"{(base_time + timedelta(seconds=5)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: AUDIT [VOICE_SERVICE] User query dispatched: 'Navigate to 742 Evergreen Terrace' [Confidence=0.98]",
        f"{(base_time + timedelta(seconds=15)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: DEBUG [BLE_DAEMON] Profile MAP synchronization active for device DC:E5:5B:22:90:AF",
        f"{(base_time + timedelta(seconds=25)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: WARN [ADAS_FCW] Forward collision warning active - Target distance 48m, closure rate 22m/s",
        f"{(base_time + timedelta(seconds=28)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: AUDIT [VOICE_SERVICE] User query dispatched: 'Read the last incoming message from Sarah' [Confidence=0.96]",
        f"{(base_time + timedelta(seconds=32)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: ALERT [CHASSIS_CAN] AEB_TRIGGER: Hydraulic brake boost applied 85% at speed 93.3 kph",
        f"{(base_time + timedelta(seconds=35)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: CRITICAL [AIRBAG_ECU] Collision detected. Delta-V X=-42km/h, Y=+8km/h. DTC B0001-13 set.",
        f"{(base_time + timedelta(seconds=36)).strftime('%b %d %H:%M:%S')} oem-gateway-us-west[4012]: CRITICAL [TCU_ECALL] Triggering automatic collision notification (ACN) to PSAP. Lat=37.7801 Lon=-122.4152"
    ]
    with open(syslog_path, "w", encoding="utf-8") as f:
        f.write("\n".join(syslog_lines) + "\n")

    return {
        "telematics_json": telematics_path,
        "ivi_sqlite": ivi_db_path,
        "gateway_syslog": syslog_path
    }

if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "raw_evidence_source")
    files = generate_evidence_environment(out)
    print(f"[+] Synthetic vehicle evidence generated successfully in: {out}")
    for k, v in files.items():
        print(f"  - {k}: {os.path.basename(v)} ({os.path.getsize(v)} bytes)")
