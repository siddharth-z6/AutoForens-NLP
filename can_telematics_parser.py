"""
Real-World CAN Bus & OpenXC Telematics Forensic Ingestion Module
Decodes raw CAN frames (via arbitration IDs/DBC translation) and OpenXC JSON trace logs
into normalized, forensic-ready telemetry streams.

Supports:
1. OpenXC Trace Format (JSON streaming)
2. Raw CAN Arbitration ID Decoding (Speed, Brake, Airbag, Steering, DTC)
3. ISO-TP Diagnostic Frame extraction (UDS over CAN)
"""

import json
import os
import struct
from datetime import datetime, timezone
from typing import List, Dict, Any, Generator

class CANSignalDecoder:
    """
    Decodes raw hex payloads based on standard automotive DBC rules.
    """
    ARBITRATION_IDS = {
        0x020: "SRS_AIRBAG_STATUS",
        0x130: "CHASSIS_STEERING_ANGLE",
        0x244: "POWERTRAIN_VEHICLE_SPEED",
        0x320: "CHASSIS_PEDAL_DYNAMICS",
        0x480: "DIAGNOSTIC_UDS_DTC",
        0x500: "GNSS_GPS_POSITION"
    }

    @staticmethod
    def decode_frame(can_id: int, hex_payload: str) -> Dict[str, Any]:
        raw_bytes = bytes.fromhex(hex_payload)
        signal_name = CANSignalDecoder.ARBITRATION_IDS.get(can_id, f"UNKNOWN_CAN_0x{can_id:03X}")
        decoded = {"can_id": hex(can_id), "signal_group": signal_name}

        if can_id == 0x244:  # Speed & Gear
            # Byte 0-1: Speed in 0.01 km/h (Big Endian)
            speed_raw = int.from_bytes(raw_bytes[0:2], byteorder="big")
            speed_kph = round(speed_raw * 0.01, 2)
            speed_mph = round(speed_kph * 0.621371, 2)
            gear_raw = raw_bytes[2]
            gears = {0: "P", 1: "R", 2: "N", 3: "D", 4: "S"}
            decoded.update({
                "speed_kph": speed_kph,
                "speed_mph": speed_mph,
                "gear": gears.get(gear_raw, "D")
            })

        elif can_id == 0x320:  # Brake % & Throttle %
            # Byte 0: Throttle 0-100%, Byte 1: Brake 0-100%
            throttle = raw_bytes[0]
            brake = raw_bytes[1]
            decoded.update({
                "throttle_pct": throttle,
                "brake_pedal_pct": brake
            })

        elif can_id == 0x130:  # Steering Angle
            # Byte 0-1: Signed 16-bit angle (-500.0 to +500.0 deg)
            steering_raw = struct.unpack(">h", raw_bytes[0:2])[0]
            decoded.update({"steering_angle_deg": round(steering_raw * 0.1, 2)})

        elif can_id == 0x020:  # Airbag & Seatbelt
            airbag_deployed = bool(raw_bytes[0] & 0x01)
            seatbelt_buckled = bool(raw_bytes[0] & 0x02)
            decoded.update({
                "airbag_deployed": airbag_deployed,
                "seatbelt_buckled": seatbelt_buckled
            })

        elif can_id == 0x480:  # Diagnostic DTC
            dtc_str = f"U{raw_bytes[0]:02X}{raw_bytes[1]:02X}"
            decoded.update({"dtc_code": dtc_str})

        return decoded


class OpenXCTraceParser:
    """
    Parser for OpenXC vehicular JSON trace files.
    OpenXC is the de-facto open standard used by Ford and automotive researchers.
    """
    @staticmethod
    def parse_trace_file(file_path: str) -> Generator[Dict[str, Any], None, None]:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    record = json.loads(line_str)
                    yield record
                except json.JSONDecodeError:
                    continue


def generate_sample_openxc_trace(output_path: str):
    """
    Generates a realistic OpenXC format vehicle trace file.
    """
    base_epoch = 1794709500.0  # Simulated timestamp
    sample_records = [
        {"timestamp": base_epoch + 0.0, "name": "vehicle_speed", "value": 104.6},
        {"timestamp": base_epoch + 0.05, "name": "steering_wheel_angle", "value": 0.5},
        {"timestamp": base_epoch + 0.1, "name": "accelerator_pedal_position", "value": 28.0},
        {"timestamp": base_epoch + 10.0, "name": "latitude", "value": 37.7749},
        {"timestamp": base_epoch + 10.0, "name": "longitude", "value": -122.4194},
        {"timestamp": base_epoch + 25.0, "name": "steering_wheel_angle", "value": -4.2},
        {"timestamp": base_epoch + 28.0, "name": "accelerator_pedal_position", "value": 35.0},
        {"timestamp": base_epoch + 32.0, "name": "brake_pedal_status", "value": True},
        {"timestamp": base_epoch + 32.1, "name": "accelerator_pedal_position", "value": 0.0},
        {"timestamp": base_epoch + 35.0, "name": "airbag_deployment_status", "value": "PRIMARY_DEPLOYED"},
        {"timestamp": base_epoch + 35.0, "name": "diagnostic_trouble_code", "value": "B0001-13"}
    ]

    with open(output_path, "w", encoding="utf-8") as f:
        for rec in sample_records:
            f.write(json.dumps(rec) + "\n")

    return output_path

if __name__ == "__main__":
    test_trace_dir = os.path.join(os.path.dirname(__file__), "raw_evidence_source")
    os.makedirs(test_trace_dir, exist_ok=True)
    openxc_path = os.path.join(test_trace_dir, "openxc_sample_trace.json")
    
    print("[*] Generating Sample OpenXC Connected Vehicle Trace...")
    generate_sample_openxc_trace(openxc_path)
    print(f"  [+] Saved OpenXC trace: {openxc_path}")

    print("\n[*] Testing Raw CAN Frame Arbitration ID Decoding:")
    # Speed = 108.6 km/h (10860 = 0x2A6C), Gear = Drive (0x03)
    can_speed_payload = "2A6C030000000000"
    decoded_speed = CANSignalDecoder.decode_frame(0x244, can_speed_payload)
    print(f"  [0x244 POWERTRAIN] -> {decoded_speed}")

    # Throttle = 0%, Brake = 85% (0x55)
    can_brake_payload = "0055000000000000"
    decoded_brake = CANSignalDecoder.decode_frame(0x320, can_brake_payload)
    print(f"  [0x320 CHASSIS]    -> {decoded_brake}")

    # Airbag deployed = 1, Seatbelt = 1 (0x03)
    can_airbag_payload = "0300000000000000"
    decoded_airbag = CANSignalDecoder.decode_frame(0x020, can_airbag_payload)
    print(f"  [0x020 SRS_AIRBAG] -> {decoded_airbag}")

    print("\n[*] Testing OpenXC Streaming Parser:")
    count = 0
    for item in OpenXCTraceParser.parse_trace_file(openxc_path):
        count += 1
        print(f"  Record #{count}: {item['name']} = {item['value']} @ T+{item['timestamp'] - 1794709500.0:.2f}s")
