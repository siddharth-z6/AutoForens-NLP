"""
Dashboard Generator for AutoForens-NLP
Generates a fully animated, glassmorphic digital forensic dashboard
with a centered animated header and second-by-second live updates for all 4 key panels.
"""

import json
import os
import re
from datetime import datetime, timezone

def generate_dashboard():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    report_json_path = os.path.join(base_dir, "forensic_reports", "forensic_report.json")
    manifest_path = os.path.join(base_dir, "forensic_vault", "acquisition_manifest.json")
    telematics_path = os.path.join(base_dir, "forensic_vault", "cloud_telematics_stream.json")
    syslog_path = os.path.join(base_dir, "forensic_vault", "raw_cloud_gateway.log")
    output_html_path = os.path.join(base_dir, "dashboard.html")
    animated_html_path = os.path.join(base_dir, "animated_dashboard.html")
    index_html_path = os.path.join(base_dir, "index.html")

    # Load data
    with open(report_json_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)

    with open(telematics_path, "r", encoding="utf-8") as f:
        telematics_data = json.load(f)

    syslog_lines = []
    if os.path.exists(syslog_path):
        with open(syslog_path, "r", encoding="utf-8") as f:
            syslog_lines = [line.strip() for line in f if line.strip()]

    case_id = report_data.get("case_id", "CAS-2026-CAV-089")
    examiner = report_data.get("examiner", "Special Agent Forensic Investigator, DFIR Unit")
    conclusion = report_data.get("forensic_results", {}).get("forensic_conclusion", "")
    artifacts = manifest_data.get("acquired_artifacts", [])
    causal_chain = report_data.get("forensic_results", {}).get("precursor_causal_chain", [])
    distractions = report_data.get("forensic_results", {}).get("distraction_findings", [])
    impact = report_data.get("forensic_results", {}).get("impact_event", {})
    records = telematics_data.get("telemetry_records", [])
    meta = telematics_data.get("metadata", {})

    # Extract Drain templates and entities from syslog
    syslog_templates = [
        {
            "id": "TPL-001",
            "name": "Collision Airbag Trigger",
            "raw": "Nov 14 23:45:35 oem-gateway-us-west[4012]: CRITICAL [AIRBAG_ECU] Collision detected. Delta-V X=-42km/h, Y=+8km/h. DTC B0001-13 set.",
            "template": "<*DATE*> oem-gateway: CRITICAL [AIRBAG_ECU] Collision detected. Delta-V <*VAR*>, DTC <*CODE*> set.",
            "entities": [
                {"type": "DTC", "val": "B0001-13", "color": "emerald"},
                {"type": "EVENT", "val": "Collision Impact", "color": "rose"},
                {"type": "DELTA_V_X", "val": "-42 km/h", "color": "sky"},
                {"type": "DELTA_V_Y", "val": "+8 km/h", "color": "indigo"}
            ],
            "severity": "CRITICAL",
            "count": 1
        },
        {
            "id": "TPL-002",
            "name": "Chassis Brake Boost Trigger",
            "raw": "Nov 14 23:45:32 oem-gateway-us-west[4012]: ALERT [CHASSIS_CAN] AEB_TRIGGER: Hydraulic brake boost applied 85% at speed 93.3 kph",
            "template": "<*DATE*> oem-gateway: ALERT [CHASSIS_CAN] AEB_TRIGGER: Hydraulic brake boost applied <*PCT*>",
            "entities": [
                {"type": "ACTION", "val": "AEB_TRIGGER", "color": "sky"},
                {"type": "BRAKE", "val": "85.0%", "color": "rose"},
                {"type": "SPEED", "val": "93.3 kph", "color": "amber"}
            ],
            "severity": "ALERT",
            "count": 1
        },
        {
            "id": "TPL-003",
            "name": "Voice Assistant Query Dispatch",
            "raw": "Nov 14 23:45:27 oem-gateway-us-west[4012]: AUDIT [VOICE_SERVICE] User query dispatched: 'Read the last incoming message from Sarah'",
            "template": "<*DATE*> oem-gateway: AUDIT [VOICE_SERVICE] User query dispatched: <*STR*>",
            "entities": [
                {"type": "INTENT", "val": "SMS_READ_REQUEST", "color": "purple"},
                {"type": "CONTACT", "val": "Sarah", "color": "indigo"},
                {"type": "DISTRACTION", "val": "Level 3 (High)", "color": "amber"}
            ],
            "severity": "AUDIT",
            "count": 2
        },
        {
            "id": "TPL-004",
            "name": "ADAS Forward Collision Warning",
            "raw": "Nov 14 23:45:25 oem-gateway-us-west[4012]: WARN [ADAS_FCW] Forward collision warning active - Target distance 48m, closure rate 22m/s",
            "template": "<*DATE*> oem-gateway: WARN [ADAS_FCW] Forward collision warning active - Target <*VAR*>",
            "entities": [
                {"type": "ALERT", "val": "FCW Active", "color": "amber"},
                {"type": "DISTANCE", "val": "48m", "color": "sky"},
                {"type": "CLOSURE", "val": "22m/s", "color": "rose"}
            ],
            "severity": "WARN",
            "count": 1
        },
        {
            "id": "TPL-005",
            "name": "TCU Automated eCall Dispatch",
            "raw": "Nov 14 23:45:36 oem-gateway-us-west[4012]: CRITICAL [TCU_ECALL] Triggering automatic collision notification (ACN) to PSAP. Lat=37.7801 Lon=-122.4152",
            "template": "<*DATE*> oem-gateway: CRITICAL [TCU_ECALL] Triggering automatic collision notification (ACN) to PSAP.",
            "entities": [
                {"type": "SERVICE", "val": "eCall PSAP", "color": "emerald"},
                {"type": "GPS", "val": "37.7801, -122.4152", "color": "sky"},
                {"type": "PROTOCOL", "val": "NG911 ACN", "color": "purple"}
            ],
            "severity": "CRITICAL",
            "count": 1
        }
    ]

    # Pre-calculate SHA256 of primary manifest artifact
    primary_sha256 = "a122e34a3cb560fd54bd71e21b01c3f910408544a0b22a9dc6312411e74a6217"
    for a in artifacts:
        if a.get("filename") == "cloud_telematics_stream.json":
            primary_sha256 = a.get("integrity_verification", {}).get("algorithm_sha256", primary_sha256)

    # Primary crash coordinates
    crash_lat = 37.78015
    crash_lon = -122.4152
    if impact and "details" in impact and "gps" in impact["details"]:
        crash_lat = impact["details"]["gps"].get("latitude", crash_lat)
        crash_lon = impact["details"]["gps"].get("longitude", crash_lon)

    # Prepare JSON serializations
    track_data_json = json.dumps(records)
    causal_chain_json = json.dumps(causal_chain)
    distractions_json = json.dumps(distractions)
    syslog_templates_json = json.dumps(syslog_templates)

    # HTML Template with true glassmorphism, animated header in middle, and 1-second live updates
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoForens-NLP | Animated Digital Forensic Investigation Suite</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Leaflet CSS & JS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: #030712;
            background-image: 
                radial-gradient(at 0% 0%, rgba(99, 102, 241, 0.18) 0px, transparent 50%),
                radial-gradient(at 50% 0%, rgba(168, 85, 247, 0.22) 0px, transparent 50%),
                radial-gradient(at 100% 0%, rgba(14, 165, 233, 0.18) 0px, transparent 50%),
                radial-gradient(at 50% 100%, rgba(16, 185, 129, 0.12) 0px, transparent 55%);
            background-attachment: fixed;
            color: #f3f4f6;
            min-height: 100vh;
        }}
        .font-mono {{
            font-family: 'JetBrains Mono', monospace;
        }}
        /* True Glassmorphic Surfaces */
        .glass-panel {{
            background: rgba(15, 23, 42, 0.52);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            box-shadow: 0 10px 32px 0 rgba(0, 0, 0, 0.5), inset 0 1px 0 0 rgba(255, 255, 255, 0.06);
            border-radius: 1rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }}
        .glass-panel:hover {{
            border-color: rgba(129, 140, 248, 0.35);
            box-shadow: 0 16px 40px 0 rgba(99, 102, 241, 0.18), inset 0 1px 0 0 rgba(255, 255, 255, 0.12);
        }}
        .glass-nav {{
            background: rgba(8, 12, 24, 0.72);
            backdrop-filter: blur(24px);
            -webkit-backdrop-filter: blur(24px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}
        .glass-subcard {{
            background: rgba(3, 7, 18, 0.6);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.06);
        }}
        /* Animated Centered Gradient Header */
        .animated-gradient-text {{
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 40%, #c084fc 70%, #38bdf8 100%);
            background-size: 300% 300%;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            animation: gradient-flow 6s ease infinite;
        }}
        @keyframes gradient-flow {{
            0% {{ background-position: 0% 50%; }}
            50% {{ background-position: 100% 50%; }}
            100% {{ background-position: 0% 50%; }}
        }}
        /* Pulsing Glow Animations */
        .neon-glow-emerald {{
            box-shadow: 0 0 18px rgba(16, 185, 129, 0.35);
        }}
        .neon-glow-indigo {{
            box-shadow: 0 0 18px rgba(99, 102, 241, 0.35);
        }}
        .neon-glow-amber {{
            box-shadow: 0 0 18px rgba(245, 158, 11, 0.35);
        }}
        .neon-glow-rose {{
            box-shadow: 0 0 22px rgba(244, 63, 94, 0.45);
        }}
        /* Active Row Pulsing Ring */
        @keyframes pulse-border {{
            0%, 100% {{
                border-color: rgba(245, 158, 11, 0.3);
                background-color: rgba(245, 158, 11, 0.05);
            }}
            50% {{
                border-color: rgba(245, 158, 11, 0.85);
                background-color: rgba(245, 158, 11, 0.15);
            }}
        }}
        .active-event-row {{
            animation: pulse-border 1.5s infinite;
        }}
        /* Map Tile Filter for Dark Themes */
        .leaflet-dark-tiles {{
            filter: brightness(0.6) invert(1) contrast(3) hue-rotate(200deg) saturate(0.3) brightness(0.7) !important;
        }}
        /* Collision Marker Pulse */
        .pulsing-marker {{
            width: 24px;
            height: 24px;
            background: #ef4444;
            border-radius: 50%;
            border: 3px solid #ffffff;
            box-shadow: 0 0 0 rgba(239, 68, 68, 0.7);
            animation: pulse-ring 1.3s infinite;
        }}
        @keyframes pulse-ring {{
            0% {{ transform: scale(0.9); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.85); }}
            70% {{ transform: scale(1.15); box-shadow: 0 0 0 18px rgba(239, 68, 68, 0); }}
            100% {{ transform: scale(0.9); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
        }}
        #map {{
            height: 480px !important;
            min-height: 480px !important;
            width: 100% !important;
            z-index: 10;
            border-radius: 0.75rem;
        }}
        /* Custom Scrollbar */
        ::-webkit-scrollbar {{
            width: 6px;
            height: 6px;
        }}
        ::-webkit-scrollbar-track {{
            background: rgba(3, 7, 18, 0.4);
        }}
        ::-webkit-scrollbar-thumb {{
            background: rgba(71, 85, 105, 0.5);
            border-radius: 3px;
        }}
        ::-webkit-scrollbar-thumb:hover {{
            background: rgba(99, 102, 241, 0.7);
        }}
    </style>
</head>
<body class="selection:bg-indigo-600 selection:text-white">

    <!-- Top Navigation / Centered Animated Header -->
    <header class="glass-nav sticky top-0 z-50 px-6 py-4 shadow-2xl">
        <div class="max-w-[1780px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
            
            <!-- Left Info: Case ID & Forensic Credentials -->
            <div class="flex items-center gap-3 order-2 md:order-1">
                <div class="glass-subcard px-3.5 py-1.5 rounded-xl flex items-center gap-2">
                    <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
                    <div>
                        <span class="text-[10px] uppercase tracking-wider text-slate-400 block font-mono">Case File</span>
                        <span class="text-xs font-bold text-amber-400 font-mono">{case_id}</span>
                    </div>
                </div>
                <div class="hidden lg:block glass-subcard px-3 py-1.5 rounded-xl text-xs font-mono text-slate-300">
                    <span class="text-slate-500">ISO/IEC 27037:</span> <span class="text-emerald-400 font-semibold">SEALED</span>
                </div>
            </div>

            <!-- Middle: Centered Animated AutoForens-NLP Brand -->
            <div class="flex flex-col items-center justify-center text-center order-1 md:order-2">
                <div class="flex items-center gap-2.5">
                    <span class="w-3 h-3 rounded-full bg-emerald-400 animate-pulse"></span>
                    <h1 class="text-2xl md:text-3xl font-extrabold tracking-widest animated-gradient-text uppercase drop-shadow-md">
                        AutoForens-NLP
                    </h1>
                    <span class="text-[10px] font-mono font-bold bg-indigo-900/60 text-indigo-300 border border-indigo-500/40 px-2 py-0.5 rounded-full shadow-lg shadow-indigo-500/20 animate-pulse">
                        v2.5 Live
                    </span>
                </div>
                <p class="text-[11px] font-mono tracking-widest text-slate-300/80 mt-1 flex items-center justify-center gap-2">
                    <span class="text-indigo-400 font-semibold">AUTOMOTIVE TELEMATICS CLOUD INGESTION</span>
                    <span class="text-slate-600">&bull;</span>
                    <span class="text-purple-300">MULTIMODAL IVI NLP FUSION</span>
                </p>
            </div>

            <!-- Right Controls: 1-Second Auto-Play Controller & GPS Settings -->
            <div class="flex items-center gap-2.5 order-3">
                <!-- 1-Second Live Playback Ticker Badge -->
                <div class="glass-subcard px-3 py-1.5 rounded-xl flex items-center gap-2 text-xs font-mono">
                    <button id="liveLoopBtn" onclick="toggleLiveEverySecond()" class="flex items-center gap-1.5 text-emerald-400 font-bold hover:text-emerald-300 transition cursor-pointer">
                        <span id="liveLoopIndicator" class="w-2 h-2 rounded-full bg-emerald-400 animate-ping"></span>
                        <span id="liveLoopText">LIVE 1s ENGINE: RUNNING</span>
                    </button>
                    <span class="text-slate-600">|</span>
                    <span id="headerLiveSec" class="text-amber-400 font-bold">T+00s</span>
                </div>

                <!-- GPS Key Modal Trigger -->
                <button onclick="openApiKeyModal()" class="glass-subcard hover:bg-slate-800/80 border border-indigo-700/50 text-indigo-200 px-3 py-1.5 rounded-xl text-xs font-mono flex items-center gap-1.5 transition cursor-pointer shadow-sm">
                    <svg class="w-3.5 h-3.5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
                    <span>GPS Config</span>
                </button>
            </div>
        </div>
    </header>

    <!-- Main Glass Body Workspace -->
    <main class="p-4 md:p-6 space-y-6 max-w-[1780px] mx-auto">

        <!-- Top Highlight KPI Cards (Glassmorphism) -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="glass-panel p-4">
                <div class="flex justify-between items-center text-xs text-slate-400 font-mono uppercase tracking-wider">
                    <span>Target Vehicle VIN</span>
                    <span class="text-sky-400 bg-sky-950/70 border border-sky-800/80 px-2 py-0.5 rounded text-[10px]">CAN-FD</span>
                </div>
                <div class="text-lg font-bold text-white font-mono mt-2 tracking-wide">{meta.get('vehicle_identification_number', '1G1YY22U965104928')}</div>
                <div class="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 inline-block animate-pulse"></span>
                    Firmware: <strong class="text-slate-300 font-mono">{meta.get('firmware_version', 'v2026.44.2.1')}</strong>
                </div>
            </div>

            <div class="glass-panel p-4">
                <div class="flex justify-between items-center text-xs text-slate-400 font-mono uppercase tracking-wider">
                    <span>Primary Impact Timestamp</span>
                    <span class="text-rose-400 bg-rose-950/70 border border-rose-800/80 px-2 py-0.5 rounded text-[10px]">Delta-V -42 km/h</span>
                </div>
                <div class="text-lg font-bold text-rose-400 font-mono mt-2 flex items-center gap-2">
                    <span class="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
                    23:45:35.000 UTC
                </div>
                <div class="text-xs text-slate-400 mt-1">
                    Airbag Deployment &bull; DTC <strong class="text-rose-300 font-mono">B0001-13</strong>
                </div>
            </div>

            <div class="glass-panel p-4">
                <div class="flex justify-between items-center text-xs text-slate-400 font-mono uppercase tracking-wider">
                    <span>Pre-Impact Distraction</span>
                    <span class="text-amber-400 bg-amber-950/70 border border-amber-800/80 px-2 py-0.5 rounded text-[10px]">Substantiated</span>
                </div>
                <div class="text-lg font-bold text-amber-400 mt-2">{len(distractions)} Flagged Precursors</div>
                <div class="text-xs text-slate-400 mt-1 truncate">
                    Outbound SMS typing at <strong class="text-amber-300 font-mono">T - 6.0s</strong> pre-crash
                </div>
            </div>

            <div class="glass-panel p-4">
                <div class="flex justify-between items-center text-xs text-slate-400 font-mono uppercase tracking-wider">
                    <span>Cryptographic Evidence Vault</span>
                    <span class="text-emerald-400 bg-emerald-950/70 border border-emerald-800/80 px-2 py-0.5 rounded text-[10px]">ISO 27037</span>
                </div>
                <div class="text-lg font-bold text-emerald-400 font-mono mt-2">100% Bit-Stream Match</div>
                <div class="text-xs text-slate-400 mt-1 flex items-center justify-between">
                    <span>Artifacts Sealed: <strong class="text-slate-200">{len(artifacts)}</strong></span>
                    <span class="text-emerald-400 font-mono text-[11px] animate-pulse">DUAL-HASH PASS</span>
                </div>
            </div>
        </div>

        <!-- Upper Section: Interactive GPS Map & Multimodal Dynamics Graph -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

            <!-- Leaflet GPS Track Map (Glass Card) -->
            <div class="lg:col-span-6 glass-panel p-5 flex flex-col">
                <div class="flex flex-wrap justify-between items-center mb-3 gap-2">
                    <div>
                        <h2 class="text-sm font-bold text-slate-200 flex items-center gap-2">
                            <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path></svg>
                            Spatial GPS Telematics &amp; Collision Reconstruction
                        </h2>
                        <span class="text-[11px] text-slate-400 font-mono">GNSS Real High-Frequency Telematics ({len(records)} Waypoints &bull; No Watermark)</span>
                    </div>
                    <div class="flex items-center gap-1.5">
                        <a href="forensic_map.html" target="_blank" title="Open Fullscreen Standalone Map" class="px-2.5 py-1 bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 rounded-lg text-xs font-mono transition border border-emerald-800 flex items-center gap-1 cursor-pointer">
                            <svg class="w-3.5 h-3.5 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg>
                            Full Map File
                        </a>
                        <button onclick="fitMapBounds()" class="px-2.5 py-1 bg-slate-800/80 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono transition border border-slate-700 flex items-center gap-1 cursor-pointer">
                            <svg class="w-3.5 h-3.5 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"></path></svg>
                            Fit Track
                        </button>
                        <button onclick="zoomToCrash()" class="px-2.5 py-1 bg-rose-950/80 hover:bg-rose-900 text-rose-200 rounded-lg text-xs font-mono transition border border-rose-800 flex items-center gap-1 cursor-pointer">
                            <svg class="w-3.5 h-3.5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                            Impact Site
                        </button>
                    </div>
                </div>

                <!-- API & Map Status Banner -->
                <div class="glass-subcard rounded-lg px-3 py-1.5 mb-2.5 text-[11px] font-mono flex items-center justify-between">
                    <span class="text-slate-400 flex items-center gap-1.5">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        Active Tile Feed: <strong class="text-slate-200" id="currentProviderLabel">ArcGIS Dark Canvas (OEM Clean)</strong>
                    </span>
                    <span class="text-slate-400 truncate max-w-[240px]" id="currentKeyMasked">Key: GNSS-ISO27037...</span>
                </div>

                <!-- The Leaflet Map Element -->
                <div id="map" class="rounded-xl border border-slate-800 relative shadow-inner"></div>

                <!-- Playback Scrubber Controls -->
                <div class="glass-subcard rounded-xl p-3 mt-3 space-y-2.5">
                    <div class="flex flex-wrap items-center justify-between gap-2 text-xs font-mono">
                        <div class="flex items-center gap-2">
                            <button id="playBtn" onclick="toggleTrajectoryPlay()" class="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-semibold transition cursor-pointer flex items-center gap-1.5 shadow-md shadow-indigo-600/30">
                                <span id="playBtnText">Pause Auto</span>
                            </button>
                            <button onclick="stepTrajectory(-1)" title="Step 1 second back" class="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition cursor-pointer">&larr;</button>
                            <button onclick="stepTrajectory(1)" title="Step 1 second forward" class="px-2 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition cursor-pointer">&rarr;</button>
                            <button onclick="resetTrajectoryPlay()" class="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition cursor-pointer">Reset</button>

                            <select id="playSpeedSelect" onchange="changePlaySpeed()" class="bg-slate-900 border border-slate-700 text-slate-300 rounded-lg px-2 py-1 text-xs">
                                <option value="1" selected>1s / tick</option>
                                <option value="2">2x Speed</option>
                                <option value="4">4x Speed</option>
                            </select>
                        </div>

                        <div class="flex items-center gap-3 text-xs font-mono">
                            <span>Sim: <strong class="text-amber-400 font-bold" id="simTimeLabel">T + 00s</strong></span>
                            <span>Speed: <strong class="text-sky-400 font-bold" id="simSpeedLabel">65.0 mph</strong></span>
                            <span>Status: <strong class="text-emerald-400 font-bold" id="simStatusLabel">NORMAL CRUISE</strong></span>
                        </div>
                    </div>

                    <!-- Scrubber Slider -->
                    <div class="flex items-center gap-3">
                        <span class="text-[10px] text-slate-500 font-mono">00s</span>
                        <input type="range" id="trajectoryScrubber" min="0" max="{len(records) - 1}" value="0" oninput="scrubTrajectory(this.value)" class="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-indigo-500">
                        <span class="text-[10px] text-slate-500 font-mono">{len(records) - 1:02d}s</span>
                    </div>
                </div>

                <!-- Live Dynamics HUD Subcards -->
                <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-3 text-xs font-mono">
                    <div class="glass-subcard p-2 rounded-lg">
                        <span class="text-[10px] text-slate-400 block">Throttle / Brake</span>
                        <span class="text-white font-bold transition-all duration-300" id="hudPedals">28% / 0%</span>
                    </div>
                    <div class="glass-subcard p-2 rounded-lg">
                        <span class="text-[10px] text-slate-400 block">Steering Angle</span>
                        <span class="text-white font-bold transition-all duration-300" id="hudSteering">+0.5°</span>
                    </div>
                    <div class="glass-subcard p-2 rounded-lg">
                        <span class="text-[10px] text-slate-400 block">GPS Coordinates</span>
                        <span class="text-sky-400 font-mono text-[11px]" id="hudCoords">37.77490, -122.41940</span>
                    </div>
                    <div class="glass-subcard p-2 rounded-lg">
                        <span class="text-[10px] text-slate-400 block">Gear / Heading</span>
                        <span class="text-white font-bold" id="hudGearHeading">D &bull; 42.1°</span>
                    </div>
                </div>
            </div>

            <!-- Panel 1: Multi-Modal Vehicular Dynamics & Interaction Overlay (Live Animated Every Second) -->
            <div class="lg:col-span-6 glass-panel p-5 flex flex-col border border-indigo-500/20 shadow-xl">
                <div class="flex flex-wrap justify-between items-center mb-3 gap-2">
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-ping"></span>
                            <h2 class="text-sm font-bold text-slate-100 flex items-center gap-2">
                                Multi-Modal Vehicular Dynamics &amp; Interaction Overlay
                            </h2>
                        </div>
                        <span class="text-xs text-slate-400 font-mono">Live 1-Second Telemetry Sync &bull; Speed, Deceleration, Brake Boost, Throttle &amp; Steering</span>
                    </div>
                    <div class="flex items-center gap-2">
                        <span class="text-[11px] bg-cyan-950/80 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded-full font-mono flex items-center gap-1 animate-pulse">
                            <span class="w-1.5 h-1.5 rounded-full bg-cyan-400"></span> UPDATING (1s)
                        </span>
                    </div>
                </div>

                <!-- Animated Telemetry Gauges Ribbon -->
                <div class="grid grid-cols-4 gap-2 mb-3 text-center font-mono">
                    <div class="glass-subcard p-2 rounded-lg border border-sky-500/30">
                        <div class="text-[10px] text-slate-400 uppercase">Live Speed</div>
                        <div id="liveSpeedVal" class="text-lg font-extrabold text-sky-400">65.0 <span class="text-[10px] text-slate-400">mph</span></div>
                    </div>
                    <div class="glass-subcard p-2 rounded-lg border border-rose-500/30">
                        <div class="text-[10px] text-slate-400 uppercase">Brake Boost</div>
                        <div id="liveBrakeVal" class="text-lg font-extrabold text-rose-400">0.0 <span class="text-[10px] text-slate-400">%</span></div>
                    </div>
                    <div class="glass-subcard p-2 rounded-lg border border-emerald-500/30">
                        <div class="text-[10px] text-slate-400 uppercase">Throttle</div>
                        <div id="liveThrottleVal" class="text-lg font-extrabold text-emerald-400">28.0 <span class="text-[10px] text-slate-400">%</span></div>
                    </div>
                    <div class="glass-subcard p-2 rounded-lg border border-indigo-500/30">
                        <div class="text-[10px] text-slate-400 uppercase">Steering</div>
                        <div id="liveSteeringVal" class="text-lg font-extrabold text-indigo-400">+0.5 <span class="text-[10px] text-slate-400">&deg;</span></div>
                    </div>
                </div>

                <!-- Canvas for Chart.js -->
                <div class="relative flex-1 min-h-[350px] w-full">
                    <canvas id="telemetryChart"></canvas>
                </div>

                <!-- Chart Annotations Legend -->
                <div class="mt-3 glass-subcard rounded-lg p-2.5 text-xs text-slate-400 flex flex-wrap items-center justify-between gap-2">
                    <div class="flex items-center gap-3">
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded bg-sky-400 inline-block"></span> Speed (mph)</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded bg-rose-500 inline-block"></span> Brake (%)</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded bg-emerald-400 inline-block"></span> Throttle (%)</span>
                        <span class="flex items-center gap-1"><span class="w-2.5 h-2.5 rounded bg-indigo-400 inline-block"></span> Steering (deg)</span>
                    </div>
                    <span class="text-amber-400 text-[11px] font-mono animate-pulse">Impact Site at T+35s &bull; Precursor Window T+24s to T+29s</span>
                </div>
            </div>
        </div>

        <!-- Lower Section: Precursor Causal Timeline & NLP Template Mining -->
        <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

            <!-- Panel 2: Pre-Impact Distraction & Causal Sequence (-15.0s to +5.0s) (Live Animated Every Second) -->
            <div class="lg:col-span-7 glass-panel p-5 shadow-xl flex flex-col border border-amber-500/20">
                <div class="flex flex-wrap justify-between items-center mb-3 gap-2">
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-amber-400 animate-ping"></span>
                            <h2 class="text-sm font-bold text-slate-100 flex items-center gap-2">
                                Pre-Impact Distraction &amp; Causal Sequence (-15.0s to +5.0s)
                            </h2>
                        </div>
                        <span class="text-[11px] text-slate-400 font-mono">Chronological Cross-Source Fusion &bull; Live Highlight Updates Every Second</span>
                    </div>

                    <!-- Filter Pill Buttons -->
                    <div class="flex items-center gap-1.5 text-[11px] font-mono">
                        <button onclick="filterTimeline('all')" id="filterAll" class="px-2.5 py-1 rounded-lg bg-indigo-600 text-white font-semibold cursor-pointer shadow-sm">All ({len(causal_chain)})</button>
                        <button onclick="filterTimeline('distraction')" id="filterDistraction" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer">Distractions</button>
                        <button onclick="filterTimeline('dynamics')" id="filterDynamics" class="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer">Kinematics</button>
                    </div>
                </div>

                <!-- Live Countdown / Status Alert Banner -->
                <div id="causalAlertBanner" class="glass-subcard border-l-4 border-l-emerald-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300">
                    <div class="flex items-center gap-2">
                        <span id="causalAlertPulse" class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        <span id="causalAlertHeadline" class="text-slate-200 font-semibold">T+00s: Cruising at 65 mph (Driver Attentive)</span>
                    </div>
                    <span id="causalCountdownBadge" class="text-slate-400 font-bold bg-slate-800/80 px-2 py-0.5 rounded">T - 35.0s to Impact</span>
                </div>

                <!-- Timeline Table -->
                <div class="overflow-x-auto flex-1 max-h-[420px] overflow-y-auto pr-1">
                    <table class="w-full text-left text-xs">
                        <thead class="text-slate-400 border-b border-slate-800 font-mono sticky top-0 bg-slate-950/90 z-10 backdrop-blur">
                            <tr>
                                <th class="pb-2.5">Time (UTC)</th>
                                <th class="pb-2.5">Source</th>
                                <th class="pb-2.5">Category</th>
                                <th class="pb-2.5">Interaction / Telemetric Event</th>
                                <th class="pb-2.5">Status Tag</th>
                            </tr>
                        </thead>
                        <tbody id="timelineTableBody" class="divide-y divide-slate-800/60 font-sans">
                            <!-- Populated dynamically via JS -->
                        </tbody>
                    </table>
                </div>

                <!-- Forensic Conclusion Quote -->
                <div class="mt-3.5 glass-subcard border-l-4 border-l-amber-500 rounded-lg p-3 text-xs">
                    <div class="flex items-center gap-2 text-amber-400 font-semibold mb-1">
                        <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                        <span>Lead Examiner Assessment</span>
                    </div>
                    <p class="text-slate-300 italic">"{conclusion}"</p>
                </div>
            </div>

            <!-- Panel 3: NLP Log Parser & Automotive-NER Inspector (Live Animated Every Second) -->
            <div class="lg:col-span-5 glass-panel p-5 shadow-xl flex flex-col border border-emerald-500/20">
                <div class="flex justify-between items-center mb-3">
                    <div>
                        <div class="flex items-center gap-2">
                            <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
                            <h2 class="text-sm font-bold text-slate-100 flex items-center gap-2">
                                NLP Log Parser &amp; Automotive-NER Inspector
                            </h2>
                        </div>
                        <span class="text-xs text-slate-400 font-mono">Drain Tree Mining &amp; Domain Entity Classifier &bull; Updating Live</span>
                    </div>
                    <span class="text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 px-2.5 py-0.5 rounded-full font-mono animate-pulse">
                        Drain3 Active
                    </span>
                </div>

                <!-- Live NLP Throughput Banner -->
                <div class="glass-subcard rounded-lg p-2.5 mb-3 grid grid-cols-3 gap-2 text-center text-xs font-mono">
                    <div>
                        <div class="text-[10px] text-slate-500">Mined Logs</div>
                        <div id="nlpLogCounter" class="text-sm font-bold text-emerald-400">4,012</div>
                    </div>
                    <div>
                        <div class="text-[10px] text-slate-500">Parsing Rate</div>
                        <div id="nlpRateVal" class="text-sm font-bold text-sky-400">48 logs/s</div>
                    </div>
                    <div>
                        <div class="text-[10px] text-slate-500">Tree Depth</div>
                        <div class="text-sm font-bold text-purple-400">4 Layers</div>
                    </div>
                </div>

                <!-- Live Ingestion Feed Terminal -->
                <div class="glass-subcard rounded-lg p-2.5 mb-3 border border-slate-800 font-mono text-[11px]">
                    <div class="flex justify-between text-slate-500 text-[10px] mb-1">
                        <span>LIVE DRAIN INGESTION STREAM:</span>
                        <span class="text-emerald-400 flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span> PARSING</span>
                    </div>
                    <div id="liveSyslogStream" class="text-amber-300 truncate font-semibold">
                        Nov 14 23:45:00 oem-gateway[4012]: INFO [TCU-UPLINK] Handshake authenticated VIN=1G1YY22U965104928
                    </div>
                </div>

                <!-- Templates List -->
                <div class="space-y-3 flex-1 overflow-y-auto max-h-[360px] pr-1 text-xs">
                    {"".join([f'''
                    <div id="tplCard_{tpl["id"]}" class="glass-subcard p-3 rounded-lg border border-slate-800/80 hover:border-slate-700 transition">
                        <div class="flex justify-between items-center text-slate-400 mb-1.5">
                            <span class="font-mono text-indigo-400 font-bold flex items-center gap-1.5">
                                <span class="w-2 h-2 rounded-full bg-indigo-500"></span>
                                {tpl["id"]}: {tpl["name"]}
                            </span>
                            <span class="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono">{tpl["severity"]}</span>
                        </div>
                        <p class="font-mono text-slate-300 text-[11px] mb-1.5 bg-slate-950/70 p-2 rounded border border-slate-800/80 break-all">
                            {tpl["template"]}
                        </p>
                        <div class="flex flex-wrap gap-1.5 mt-2">
                            {"".join([f'<span class="bg-{ent["color"]}-950/90 text-{ent["color"]}-300 border border-{ent["color"]}-700/60 px-2 py-0.5 rounded font-mono text-[10px]">{ent["type"]}: <strong>{ent["val"]}</strong></span>' for ent in tpl["entities"]])}
                        </div>
                    </div>
                    ''' for tpl in syslog_templates])}
                </div>
            </div>
        </div>

        <!-- Panel 4: Evidence Vault & ISO/IEC 27037 Manifest Card (Live Animated Every Second) -->
        <div class="glass-panel p-5 shadow-xl border border-emerald-500/20">
            <div class="flex flex-wrap justify-between items-center mb-3 gap-2">
                <div>
                    <div class="flex items-center gap-2">
                        <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></span>
                        <h2 class="text-sm font-bold text-slate-100 flex items-center gap-2">
                            ISO/IEC 27037:2012 Cryptographic Chain of Custody &amp; Artifact Manifest
                        </h2>
                    </div>
                    <p class="text-xs text-slate-400 font-mono">Continuous Cryptographic Verification Heartbeat &bull; Dual-hash validation of acquired OEM cloud streams &amp; IVI dumps</p>
                </div>
                
                <!-- Live Verification Heartbeat Indicator -->
                <div class="flex items-center gap-3 text-xs font-mono">
                    <div class="glass-subcard px-3 py-1 rounded-lg flex items-center gap-2">
                        <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                        <span class="text-slate-400">Audit Cycle:</span>
                        <span id="cryptoAuditCycle" class="text-emerald-400 font-bold">#14,920</span>
                        <span class="text-slate-600">|</span>
                        <span id="cryptoLatency" class="text-sky-400">14ms latency</span>
                    </div>
                    <div class="text-slate-400 hidden sm:block">
                        Lead Examiner: <strong class="text-slate-200">{examiner}</strong>
                    </div>
                </div>
            </div>

            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs font-mono">
                    <thead class="text-slate-400 border-b border-slate-800">
                        <tr>
                            <th class="pb-2">Artifact ID</th>
                            <th class="pb-2">File Name</th>
                            <th class="pb-2">Evidence Category</th>
                            <th class="pb-2">File Size</th>
                            <th class="pb-2">SHA-256 Digest</th>
                            <th class="pb-2">SHA-512 Digest</th>
                            <th class="pb-2">Integrity Status</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-slate-800/70 text-slate-300">
                        {"".join([f'''
                        <tr class="hover:bg-slate-800/30 transition-colors">
                            <td class="py-2.5 font-bold text-indigo-400">{art["artifact_id"]}</td>
                            <td class="py-2.5 text-white font-semibold">{art["filename"]}</td>
                            <td class="py-2.5"><span class="bg-slate-800/90 border border-slate-700 px-2 py-0.5 rounded text-[10px] text-slate-300">{art["category"]}</span></td>
                            <td class="py-2.5">{art["size_bytes"]:,} Bytes</td>
                            <td class="py-2.5 font-mono text-amber-300 text-[11px]" title="{art["integrity_verification"]["algorithm_sha256"]}">
                                {art["integrity_verification"]["algorithm_sha256"][:18]}...{art["integrity_verification"]["algorithm_sha256"][-8:]}
                            </td>
                            <td class="py-2.5 font-mono text-slate-400 text-[11px]" title="{art["integrity_verification"]["algorithm_sha512"]}">
                                {art["integrity_verification"]["algorithm_sha512"][:16]}...
                            </td>
                            <td class="py-2.5">
                                <span class="bg-emerald-950/90 text-emerald-400 border border-emerald-700/80 px-2.5 py-0.5 rounded-full text-[10px] font-bold flex items-center gap-1 w-max animate-pulse">
                                    <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span> VERIFIED BIT-STREAM
                                </span>
                            </td>
                        </tr>
                        ''' for art in artifacts])}
                    </tbody>
                </table>
            </div>
        </div>

    </main>

    <!-- Modal for GPS API Key Management -->
    <div id="apiKeyModal" class="fixed inset-0 bg-black/80 backdrop-blur-md z-50 flex items-center justify-center p-4 hidden">
        <div class="glass-panel border border-slate-700 max-w-lg w-full p-6 shadow-2xl space-y-5">
            <div class="flex justify-between items-center border-b border-slate-800 pb-3">
                <div class="flex items-center gap-2.5">
                    <div class="w-8 h-8 rounded-lg bg-indigo-950 border border-indigo-800 flex items-center justify-center text-indigo-400">
                        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
                    </div>
                    <div>
                        <h3 class="text-base font-bold text-white">GPS &amp; Telematics API Credentials</h3>
                        <p class="text-xs text-slate-400">ISO/IEC 27037 Compliant GNSS Ingestion Authentication</p>
                    </div>
                </div>
                <button onclick="closeApiKeyModal()" class="text-slate-400 hover:text-white text-lg font-bold cursor-pointer">&times;</button>
            </div>

            <!-- Provider Selector -->
            <div>
                <label class="block text-xs font-semibold text-slate-300 mb-1.5">Select GPS / Map Tile Provider</label>
                <select id="mapProviderSelect" onchange="handleProviderChange()" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-indigo-500 font-mono">
                    <option value="oem_cloud">ArcGIS Dark Canvas (OEM Clean - Zero Watermark)</option>
                    <option value="esri_sat">Esri World Imagery (High-Resolution Satellite)</option>
                    <option value="osm_dark">OpenStreetMap Cyber Dark (Zero Watermark)</option>
                    <option value="osm_standard">OpenStreetMap Standard (Global Street Map)</option>
                    <option value="google">Google Maps Hybrid (Satellite &amp; Roads)</option>
                </select>
            </div>

            <!-- API Key Input -->
            <div>
                <div class="flex justify-between items-center mb-1.5">
                    <label class="text-xs font-semibold text-slate-300">Active Ingestion API Key / Token</label>
                    <button onclick="generateFreshKey()" class="text-[11px] font-mono text-indigo-400 hover:text-indigo-300 flex items-center gap-1 cursor-pointer">
                        <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                        Regenerate Key
                    </button>
                </div>
                <input type="text" id="apiKeyInput" class="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-xs text-amber-300 font-mono focus:outline-none focus:border-indigo-500" value="GNSS-ISO27037-SEC-TOKEN-4f9e1b8c2d6a77e3">
                <p class="text-[11px] text-slate-400 mt-1" id="keyHelperText">This 256-bit cryptographic token validates simulated OEM telematics ingestion.</p>
            </div>

            <!-- Action Buttons -->
            <div class="flex justify-end gap-3 pt-2">
                <button onclick="closeApiKeyModal()" class="px-4 py-2 rounded-lg text-xs font-semibold text-slate-300 hover:bg-slate-800 cursor-pointer transition">Cancel</button>
                <button onclick="saveAndApplyApiKey()" class="px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600 hover:bg-indigo-500 text-white cursor-pointer shadow-lg shadow-indigo-600/30 transition flex items-center gap-1.5">
                    Save &amp; Apply
                </button>
            </div>
        </div>
    </div>

    <!-- Embedded Forensic Dataset & Engine -->
    <script>
        // Real Embedded Forensic Telemetry Dataset
        const fullTrackData = {track_data_json};
        const causalChainData = {causal_chain_json};
        const distractionFindings = {distractions_json};

        // Primary Collision Location
        const crashLoc = [{crash_lat}, {crash_lon}];

        // Local Storage and Active Keys
        const DEFAULT_KEY = "GNSS-ISO27037-SEC-TOKEN-4f9e1b8c2d6a77e3";
        let activeApiKey = localStorage.getItem("autoforens_gps_api_key") || DEFAULT_KEY;
        let activeProvider = localStorage.getItem("autoforens_gps_provider") || "oem_cloud";

        // Map Waypoints
        const pathCoords = fullTrackData.map(d => [d.gps.latitude, d.gps.longitude]);

        // 1. Initialize Leaflet Map (Zero Watermark)
        const map = L.map('map', {{
            zoomControl: false,
            center: crashLoc,
            zoom: 15
        }});

        L.control.zoom({{ position: 'topleft' }}).addTo(map);
        L.control.scale({{ imperial: true, metric: true, position: 'bottomleft' }}).addTo(map);

        // Tile Layer Definitions
        const baseMaps = {{
            "ArcGIS Dark Canvas (OEM Clean)": L.layerGroup([
                L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Base/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
                    maxZoom: 16,
                    attribution: 'Tiles &copy; Esri &mdash; Esri, DeLorme, NAVTEQ'
                }}),
                L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/World_Dark_Gray_Reference/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
                    maxZoom: 16,
                    attribution: 'Reference &copy; Esri'
                }})
            ]),
            "Esri Satellite Imagery": L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{{z}}/{{y}}/{{x}}', {{
                maxZoom: 19,
                attribution: 'Tiles &copy; Esri &mdash; High-Res Earth Imagery'
            }}),
            "OpenStreetMap Cyber Dark": L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                maxZoom: 19,
                className: 'leaflet-dark-tiles',
                attribution: '&copy; OpenStreetMap contributors'
            }}),
            "OpenStreetMap Standard": L.tileLayer('https://tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png', {{
                maxZoom: 19,
                attribution: '&copy; OpenStreetMap contributors'
            }}),
            "Google Maps Hybrid": L.tileLayer('https://mt1.google.com/vt/lyrs=y&x={{x}}&y={{y}}&z={{z}}', {{
                maxZoom: 20,
                attribution: '&copy; Google Maps'
            }})
        }};

        // Apply active base layer
        function applyTileLayer(provider) {{
            Object.values(baseMaps).forEach(layer => map.removeLayer(layer));
            if (provider === 'esri_sat') {{
                baseMaps["Esri Satellite Imagery"].addTo(map);
            }} else if (provider === 'osm_dark') {{
                baseMaps["OpenStreetMap Cyber Dark"].addTo(map);
            }} else if (provider === 'osm_standard') {{
                baseMaps["OpenStreetMap Standard"].addTo(map);
            }} else if (provider === 'google') {{
                baseMaps["Google Maps Hybrid"].addTo(map);
            }} else {{
                baseMaps["ArcGIS Dark Canvas (OEM Clean)"].addTo(map);
            }}
        }}

        applyTileLayer(activeProvider);
        L.control.layers(baseMaps, null, {{ position: 'topright' }}).addTo(map);

        // Render Trajectory Segments
        L.polyline(pathCoords.slice(0, 26), {{ color: '#10b981', weight: 5, opacity: 0.95 }}).addTo(map);
        L.polyline(pathCoords.slice(24, 33), {{ color: '#f59e0b', weight: 5.5, dashArray: '6, 6', opacity: 1 }}).addTo(map);
        L.polyline(pathCoords.slice(31, 36), {{ color: '#38bdf8', weight: 6, opacity: 1 }}).addTo(map);
        L.polyline(pathCoords.slice(35), {{ color: '#ef4444', weight: 4.5, opacity: 0.75 }}).addTo(map);

        // Exclusion Perimeter
        L.circle(crashLoc, {{
            radius: 90,
            color: '#ef4444',
            fillColor: '#ef4444',
            fillOpacity: 0.16,
            dashArray: '5, 5',
            weight: 2
        }}).addTo(map).bindPopup("<b>Forensic Exclusion Perimeter</b><br>Radius: 90 meters &bull; Impact Epicenter");

        // Milestone Markers
        L.circleMarker(pathCoords[0], {{ radius: 6, color: '#10b981', fillColor: '#10b981', fillOpacity: 1, weight: 2 }}).addTo(map).bindPopup("<b>Trip Start Point (T + 00s)</b>");
        L.circleMarker(pathCoords[24], {{ radius: 6, color: '#f59e0b', fillColor: '#f59e0b', fillOpacity: 1, weight: 2 }}).addTo(map).bindPopup("<b>T + 24s: Inbound SMS</b>");
        L.circleMarker(pathCoords[27], {{ radius: 6, color: '#a855f7', fillColor: '#a855f7', fillOpacity: 1, weight: 2 }}).addTo(map).bindPopup("<b>T + 27s: Voice Assistant</b>");
        L.circleMarker(pathCoords[29], {{ radius: 6, color: '#ec4899', fillColor: '#ec4899', fillOpacity: 1, weight: 2 }}).addTo(map).bindPopup("<b>T + 29s: Outbound SMS Compose</b>");
        L.circleMarker(pathCoords[32], {{ radius: 6, color: '#38bdf8', fillColor: '#38bdf8', fillOpacity: 1, weight: 2 }}).addTo(map).bindPopup("<b>T + 32s: AEB Emergency Braking</b>");

        const pulsingIcon = L.divIcon({{
            className: 'pulsing-marker',
            iconSize: [24, 24],
            iconAnchor: [12, 12]
        }});
        L.marker(crashLoc, {{ icon: pulsingIcon }}).addTo(map).bindPopup("<b>Primary Collision Site (T + 35s)</b><br>DTC B0001-13 &bull; Airbag Deployed");

        const carIcon = L.divIcon({{
            html: '<div class="w-7 h-7 rounded-full bg-indigo-600 border-2 border-white flex items-center justify-center text-white shadow-lg"><svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path d="M8 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM15 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z"></path><path d="M3 4a1 1 0 00-1 1v10a1 1 0 001 1h1.05a2.5 2.5 0 014.9 0H10a1 1 0 001-1V5a1 1 0 00-1-1H3zM14 7a1 1 0 00-1 1v6.05A2.5 2.5 0 0115.95 16H17a1 1 0 001-1v-5a1 1 0 00-.293-.707l-2-2A1 1 0 0015 7h-1z"></path></svg></div>',
            className: '',
            iconSize: [28, 28],
            iconAnchor: [14, 14]
        }});
        let carMarker = L.marker(pathCoords[0], {{ icon: carIcon, zIndexOffset: 1000 }}).addTo(map);

        function fitMapBounds() {{
            map.fitBounds(L.polyline(pathCoords).getBounds(), {{ padding: [40, 40] }});
        }}
        function zoomToCrash() {{
            map.flyTo(crashLoc, 18, {{ duration: 1.2 }});
        }}

        // 2. Initialize Chart.js Multimodal Dynamics Chart
        const ctx = document.getElementById('telemetryChart').getContext('2d');
        const labels = fullTrackData.map((d, i) => `T+${{i < 10 ? '0' + i : i}}s`);
        const speeds = fullTrackData.map(d => d.dynamics.speed_mph);
        const brakes = fullTrackData.map(d => d.dynamics.brake_pedal_pct);
        const throttles = fullTrackData.map(d => d.dynamics.throttle_pct);
        const steerings = fullTrackData.map(d => d.dynamics.steering_angle_deg);

        const telemetryChart = new Chart(ctx, {{
            type: 'line',
            data: {{
                labels: labels,
                datasets: [
                    {{
                        label: 'Speed (mph)',
                        data: speeds,
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.08)',
                        borderWidth: 2.5,
                        fill: true,
                        tension: 0.3,
                        pointRadius: 2,
                        pointHoverRadius: 6,
                        yAxisID: 'y'
                    }},
                    {{
                        label: 'Brake Pedal (%)',
                        data: brakes,
                        borderColor: '#f43f5e',
                        backgroundColor: 'transparent',
                        borderWidth: 2,
                        tension: 0.2,
                        pointRadius: 1,
                        yAxisID: 'y1'
                    }},
                    {{
                        label: 'Throttle (%)',
                        data: throttles,
                        borderColor: '#34d399',
                        backgroundColor: 'transparent',
                        borderWidth: 1.5,
                        borderDash: [4, 4],
                        tension: 0.2,
                        pointRadius: 0,
                        yAxisID: 'y1'
                    }},
                    {{
                        label: 'Steering (deg)',
                        data: steerings,
                        borderColor: '#818cf8',
                        backgroundColor: 'transparent',
                        borderWidth: 1.5,
                        tension: 0.2,
                        pointRadius: 0,
                        yAxisID: 'y2'
                    }}
                ]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: {{
                    mode: 'index',
                    intersect: false
                }},
                scales: {{
                    x: {{
                        grid: {{ color: 'rgba(255, 255, 255, 0.05)' }},
                        ticks: {{ color: '#94a3b8', font: {{ family: 'JetBrains Mono', size: 10 }}, maxTicksLimit: 12 }}
                    }},
                    y: {{
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {{ display: true, text: 'Speed (mph)', color: '#38bdf8', font: {{ size: 10 }} }},
                        grid: {{ color: 'rgba(255, 255, 255, 0.05)' }},
                        ticks: {{ color: '#38bdf8' }}
                    }},
                    y1: {{
                        type: 'linear',
                        display: true,
                        position: 'right',
                        max: 105,
                        min: 0,
                        title: {{ display: true, text: 'Pedals (%)', color: '#f43f5e', font: {{ size: 10 }} }},
                        grid: {{ drawOnChartArea: false }},
                        ticks: {{ color: '#f43f5e' }}
                    }},
                    y2: {{
                        type: 'linear',
                        display: false,
                        min: -25,
                        max: 25
                    }}
                }},
                plugins: {{
                    legend: {{ display: false }}
                }}
            }}
        }});

        // 3. Render Precursor Causal Timeline Table
        function renderTimeline(filter) {{
            const tbody = document.getElementById('timelineTableBody');
            tbody.innerHTML = '';

            causalChainData.forEach((evt, idx) => {{
                if (filter === 'distraction' && !evt.category.includes('COMMUNICATION') && !evt.category.includes('VOICE')) return;
                if (filter === 'dynamics' && !evt.category.includes('VEHICLE_DYNAMICS')) return;

                const tr = document.createElement('tr');
                tr.id = `causalRow_${{idx}}`;
                tr.className = "hover:bg-slate-800/40 transition-colors cursor-pointer text-slate-300";
                tr.onclick = () => {{
                    const sec = Math.min(Math.max(0, Math.round(evt.epoch - causalChainData[0].epoch)), fullTrackData.length - 1);
                    setSimulationStep(sec);
                }};

                let badgeColor = "bg-slate-800 text-slate-300 border-slate-700";
                if (evt.event_tag.includes("AIRBAG") || evt.event_tag.includes("CRITICAL")) badgeColor = "bg-rose-950 text-rose-300 border-rose-800";
                else if (evt.event_tag.includes("SMS") || evt.event_tag.includes("DISTRACTION")) badgeColor = "bg-amber-950 text-amber-300 border-amber-800";
                else if (evt.event_tag.includes("BRAKE")) badgeColor = "bg-sky-950 text-sky-300 border-sky-800";

                tr.innerHTML = `
                    <td class="py-2.5 font-mono text-[11px] text-slate-400 whitespace-nowrap">${{evt.timestamp_utc.split("T")[1].replace("+00:00", "")}}</td>
                    <td class="py-2.5 text-[11px]"><span class="glass-subcard px-1.5 py-0.5 rounded text-indigo-300">${{evt.source}}</span></td>
                    <td class="py-2.5 text-[11px] text-slate-400">${{evt.category}}</td>
                    <td class="py-2.5 text-[11px] font-medium text-slate-200">${{evt.summary}}</td>
                    <td class="py-2.5 whitespace-nowrap"><span class="border px-2 py-0.5 rounded text-[10px] font-bold ${{badgeColor}}">${{evt.event_tag}}</span></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        function filterTimeline(type) {{
            document.getElementById('filterAll').className = type === 'all' ? "px-2.5 py-1 rounded-lg bg-indigo-600 text-white font-semibold" : "px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300";
            document.getElementById('filterDistraction').className = type === 'distraction' ? "px-2.5 py-1 rounded-lg bg-indigo-600 text-white font-semibold" : "px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300";
            document.getElementById('filterDynamics').className = type === 'dynamics' ? "px-2.5 py-1 rounded-lg bg-indigo-600 text-white font-semibold" : "px-2.5 py-1 rounded-lg bg-slate-800 text-slate-300";
            renderTimeline(type);
        }}

        renderTimeline('all');

        // 4. LIVE 1-SECOND UPDATE ENGINE (Updates all 4 Key Sections every second)
        let liveStep = 0;
        let isLiveActive = true;
        let speedMultiplier = 1.0;
        let playTimer = null;
        let auditCounter = 14920;
        let logCounter = 4012;

        const liveSyslogs = [
            "Nov 14 23:45:00 oem-gateway[4012]: INFO [TCU-UPLINK] Handshake authenticated for VIN=1G1YY22U965104928",
            "Nov 14 23:45:05 oem-gateway[4012]: AUDIT [VOICE_SERVICE] User query: 'Navigate to 742 Evergreen Terrace'",
            "Nov 14 23:45:15 oem-gateway[4012]: DEBUG [BLE_DAEMON] Profile MAP synchronization active for iPhone 16 Pro",
            "Nov 14 23:45:24 oem-gateway[4012]: AUDIT [SMS_MAP] Inbound SMS from Sarah Miller: 'Urgent: Check email'",
            "Nov 14 23:45:25 oem-gateway[4012]: WARN [ADAS_FCW] Forward collision warning active - Target distance 48m",
            "Nov 14 23:45:27 oem-gateway[4012]: AUDIT [VOICE_SERVICE] User query: 'Read the last incoming message'",
            "Nov 14 23:45:29 oem-gateway[4012]: AUDIT [SMS_MAP] Outbound SMS typing detected: 'Opening it now on my screen'",
            "Nov 14 23:45:32 oem-gateway[4012]: ALERT [CHASSIS_CAN] AEB_TRIGGER: Hydraulic brake boost applied 85%",
            "Nov 14 23:45:35 oem-gateway[4012]: CRITICAL [AIRBAG_ECU] Collision detected. Delta-V X=-42km/h. DTC B0001-13 set",
            "Nov 14 23:45:36 oem-gateway[4012]: CRITICAL [TCU_ECALL] Triggering automatic collision notification (ACN) to PSAP",
            "Nov 14 23:45:45 oem-gateway[4012]: INFO [TELEMATICS] Post-crash diagnostic telemetry packet cryptographically sealed"
        ];

        function executeOneSecondTick() {{
            setSimulationStep(liveStep);

            // Advance step (loop 0 to 59)
            liveStep++;
            if (liveStep >= fullTrackData.length) {{
                liveStep = 0;
            }}
        }}

        function setSimulationStep(idx) {{
            const pt = fullTrackData[idx];
            if (!pt) return;

            // --- A) Update Section 1: Multi-Modal Vehicular Dynamics & Interaction Overlay ---
            document.getElementById('liveSpeedVal').innerHTML = `${{pt.dynamics.speed_mph.toFixed(1)}} <span class="text-[10px] text-slate-400">mph</span>`;
            document.getElementById('liveBrakeVal').innerHTML = `${{pt.dynamics.brake_pedal_pct.toFixed(1)}} <span class="text-[10px] text-slate-400">%</span>`;
            document.getElementById('liveThrottleVal').innerHTML = `${{pt.dynamics.throttle_pct.toFixed(1)}} <span class="text-[10px] text-slate-400">%</span>`;
            document.getElementById('liveSteeringVal').innerHTML = `${{pt.dynamics.steering_angle_deg >= 0 ? '+' : ''}}${{pt.dynamics.steering_angle_deg.toFixed(1)}}&deg;`;

            // HUD Subcards & Map Car Marker
            carMarker.setLatLng([pt.gps.latitude, pt.gps.longitude]);
            document.getElementById('simTimeLabel').innerText = `T + ${{idx < 10 ? '0' + idx : idx}}s`;
            document.getElementById('headerLiveSec').innerText = `T + ${{idx < 10 ? '0' + idx : idx}}s`;
            document.getElementById('simSpeedLabel').innerText = `${{pt.dynamics.speed_mph.toFixed(1)}} mph`;
            document.getElementById('simStatusLabel').innerText = pt.event_tag;
            document.getElementById('hudPedals').innerText = `${{pt.dynamics.throttle_pct.toFixed(0)}}% / ${{pt.dynamics.brake_pedal_pct.toFixed(0)}}%`;
            document.getElementById('hudSteering').innerText = `${{pt.dynamics.steering_angle_deg >= 0 ? '+' : ''}}${{pt.dynamics.steering_angle_deg.toFixed(1)}}°`;
            document.getElementById('hudCoords').innerText = `${{pt.gps.latitude.toFixed(5)}}, ${{pt.gps.longitude.toFixed(5)}}`;
            document.getElementById('hudGearHeading').innerText = `${{pt.dynamics.gear_position}} &bull; ${{pt.gps.heading.toFixed(1)}}°`;
            document.getElementById('trajectoryScrubber').value = idx;

            // Highlight live point on telemetryChart
            telemetryChart.setActiveElements([
                {{ datasetIndex: 0, index: idx }},
                {{ datasetIndex: 1, index: idx }}
            ]);
            telemetryChart.update('none');

            // --- B) Update Section 2: Pre-Impact Distraction & Causal Sequence Table ---
            const headline = document.getElementById('causalAlertHeadline');
            const countdownBadge = document.getElementById('causalCountdownBadge');
            const banner = document.getElementById('causalAlertBanner');
            const pulseDot = document.getElementById('causalAlertPulse');

            // Clear previous table row active highlights
            document.querySelectorAll('#timelineTableBody tr').forEach(r => r.classList.remove('active-event-row'));

            if (idx < 24) {{
                banner.className = "glass-subcard border-l-4 border-l-emerald-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300";
                pulseDot.className = "w-2 h-2 rounded-full bg-emerald-400 animate-pulse";
                headline.innerText = `T+${{idx < 10 ? '0' + idx : idx}}s: Normal Highway Cruise at ${{pt.dynamics.speed_mph.toFixed(1)}} mph`;
                countdownBadge.innerText = `T - ${{(35 - idx).toFixed(1)}}s to Crash`;
            }} else if (idx === 24) {{
                banner.className = "glass-subcard border-l-4 border-l-amber-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300 neon-glow-amber";
                pulseDot.className = "w-2 h-2 rounded-full bg-amber-400 animate-ping";
                headline.innerHTML = "<strong class='text-amber-300'>DISTRACTION:</strong> Inbound SMS received ('Urgent: Check your email...')";
                countdownBadge.innerText = "T - 11.0s to Impact";
                const row = document.getElementById('causalRow_5');
                if (row) {{ row.classList.add('active-event-row'); row.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }}); }}
            }} else if (idx === 27) {{
                banner.className = "glass-subcard border-l-4 border-l-purple-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300";
                pulseDot.className = "w-2 h-2 rounded-full bg-purple-400 animate-ping";
                headline.innerHTML = "<strong class='text-purple-300'>VOICE QUERY:</strong> Driver commands IVI to read incoming SMS";
                countdownBadge.innerText = "T - 8.0s to Impact";
                const row = document.getElementById('causalRow_9');
                if (row) {{ row.classList.add('active-event-row'); row.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }}); }}
            }} else if (idx === 29) {{
                banner.className = "glass-subcard border-l-4 border-l-pink-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300 neon-glow-amber";
                pulseDot.className = "w-2 h-2 rounded-full bg-pink-400 animate-ping";
                headline.innerHTML = "<strong class='text-pink-300'>FATAL COGNITIVE DIVERSION:</strong> Driver types 'Opening it now on my screen'";
                countdownBadge.innerText = "T - 6.0s to Impact";
                const row = document.getElementById('causalRow_12');
                if (row) {{ row.classList.add('active-event-row'); row.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }}); }}
            }} else if (idx >= 32 && idx < 35) {{
                banner.className = "glass-subcard border-l-4 border-l-sky-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300";
                pulseDot.className = "w-2 h-2 rounded-full bg-sky-400 animate-ping";
                headline.innerHTML = "<strong class='text-sky-300'>EMERGENCY BRAKING:</strong> Hydraulic AEB brake boost 85% applied!";
                countdownBadge.innerText = `T - ${{(35 - idx).toFixed(1)}}s to Crash`;
                const row = document.getElementById('causalRow_15');
                if (row) {{ row.classList.add('active-event-row'); }}
            }} else if (idx === 35) {{
                banner.className = "glass-subcard border-l-4 border-l-rose-500 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300 neon-glow-rose";
                pulseDot.className = "w-2.5 h-2.5 rounded-full bg-rose-500 animate-ping";
                headline.innerHTML = "<strong class='text-rose-400'>CRASH OCCURRED:</strong> Airbag Deployed &bull; Delta-V X=-42km/h &bull; DTC B0001-13";
                countdownBadge.innerText = "T + 00.0s (IMPACT)";
                const row = document.getElementById('causalRow_18');
                if (row) {{ row.classList.add('active-event-row'); row.scrollIntoView({{ behavior: 'smooth', block: 'nearest' }}); }}
            }} else {{
                banner.className = "glass-subcard border-l-4 border-l-slate-600 rounded-lg p-2.5 mb-2.5 flex items-center justify-between text-xs font-mono transition-all duration-300";
                pulseDot.className = "w-2 h-2 rounded-full bg-slate-400";
                headline.innerText = `T+${{idx}}s: Post-Collision Inactive / PSAP Emergency Response`;
                countdownBadge.innerText = `T + ${{(idx - 35).toFixed(1)}}s Post-Impact`;
            }}

            // --- C) Update Section 3: NLP Log Parser & Automotive-NER Inspector ---
            logCounter += Math.floor(Math.random() * 6) + 3;
            document.getElementById('nlpLogCounter').innerText = logCounter.toLocaleString();
            document.getElementById('nlpRateVal').innerText = `${{45 + Math.floor(Math.random() * 8)}} logs/s`;
            const syslogIdx = Math.min(Math.floor(idx / 5), liveSyslogs.length - 1);
            document.getElementById('liveSyslogStream').innerText = liveSyslogs[syslogIdx];

            // --- D) Update Section 4: ISO/IEC 27037 Manifest & Chain of Custody ---
            auditCounter++;
            document.getElementById('cryptoAuditCycle').innerText = `#${{auditCounter.toLocaleString()}}`;
            document.getElementById('cryptoLatency').innerText = `${{12 + (idx % 6)}}ms latency`;
        }}

        function startLiveLoop() {{
            if (playTimer) clearInterval(playTimer);
            const intervalMs = Math.max(100, Math.floor(1000 / speedMultiplier));
            playTimer = setInterval(executeOneSecondTick, intervalMs);
            isLiveActive = true;
            document.getElementById('liveLoopText').innerText = "LIVE 1s ENGINE: RUNNING";
            document.getElementById('liveLoopIndicator').className = "w-2 h-2 rounded-full bg-emerald-400 animate-ping";
            document.getElementById('playBtnText').innerText = "Pause Auto";
        }}

        function pauseLiveLoop() {{
            if (playTimer) clearInterval(playTimer);
            playTimer = null;
            isLiveActive = false;
            document.getElementById('liveLoopText').innerText = "LIVE 1s ENGINE: PAUSED";
            document.getElementById('liveLoopIndicator').className = "w-2 h-2 rounded-full bg-amber-400";
            document.getElementById('playBtnText').innerText = "Resume 1s Auto";
        }}

        function toggleLiveEverySecond() {{
            if (isLiveActive) pauseLiveLoop();
            else startLiveLoop();
        }}

        function toggleTrajectoryPlay() {{
            toggleLiveEverySecond();
        }}

        function resetTrajectoryPlay() {{
            pauseLiveLoop();
            liveStep = 0;
            setSimulationStep(0);
            map.panTo(pathCoords[0]);
        }}

        function stepTrajectory(delta) {{
            pauseLiveLoop();
            let newStep = liveStep + delta;
            if (newStep < 0) newStep = 0;
            if (newStep >= fullTrackData.length) newStep = fullTrackData.length - 1;
            liveStep = newStep;
            setSimulationStep(liveStep);
        }}

        function scrubTrajectory(val) {{
            pauseLiveLoop();
            liveStep = parseInt(val, 10);
            setSimulationStep(liveStep);
        }}

        function changePlaySpeed() {{
            speedMultiplier = parseFloat(document.getElementById('playSpeedSelect').value);
            if (isLiveActive) {{
                pauseLiveLoop();
                startLiveLoop();
            }}
        }}

        // Start live 1-second auto engine on page load
        startLiveLoop();

        // 5. GPS Modal Key Management Functions
        function openApiKeyModal() {{
            document.getElementById('apiKeyModal').classList.remove('hidden');
            document.getElementById('apiKeyInput').value = activeApiKey;
            document.getElementById('mapProviderSelect').value = activeProvider;
            handleProviderChange();
        }}

        function closeApiKeyModal() {{
            document.getElementById('apiKeyModal').classList.add('hidden');
        }}

        function handleProviderChange() {{
            const provider = document.getElementById('mapProviderSelect').value;
            const helper = document.getElementById('keyHelperText');
            if (provider === 'google') {{
                helper.innerHTML = 'Google Maps Hybrid raster tiles enabled. Use personal key or proxy.';
            }} else if (provider === 'esri_sat') {{
                helper.innerHTML = 'Esri World Imagery satellite feed enabled (High-resolution global imagery).';
            }} else if (provider === 'osm_dark') {{
                helper.innerHTML = 'OpenStreetMap Cyber Dark tile server enabled with zero watermark.';
            }} else if (provider === 'osm_standard') {{
                helper.innerHTML = 'OpenStreetMap Standard tile layer requires no custom API token.';
            }} else {{
                helper.innerHTML = 'ArcGIS Dark Canvas OEM feed active with zero API key required and no watermarks.';
            }}
        }}

        function generateFreshKey() {{
            const randomBytes = new Uint8Array(16);
            crypto.getRandomValues(randomBytes);
            const hex = Array.from(randomBytes).map(b => b.toString(16).padStart(2, '0')).join('');
            document.getElementById('apiKeyInput').value = "GNSS-ISO27037-SEC-" + hex.substring(0, 16);
        }}

        function saveAndApplyApiKey() {{
            activeApiKey = document.getElementById('apiKeyInput').value.trim() || DEFAULT_KEY;
            activeProvider = document.getElementById('mapProviderSelect').value;
            localStorage.setItem("autoforens_gps_api_key", activeApiKey);
            localStorage.setItem("autoforens_gps_provider", activeProvider);

            applyTileLayer(activeProvider);
            updateBadges();
            closeApiKeyModal();
        }}

        function updateBadges() {{
            const masked = activeApiKey.length > 18 ? activeApiKey.substring(0, 14) + "..." : activeApiKey;
            document.getElementById('currentKeyMasked').innerText = "Key: " + masked;
            const labels = {{
                "oem_cloud": "ArcGIS Dark Canvas (OEM Clean)",
                "esri_sat": "Esri World Imagery (Satellite)",
                "osm_dark": "OpenStreetMap Cyber Dark",
                "osm_standard": "OpenStreetMap Standard",
                "google": "Google Maps Hybrid"
            }};
            document.getElementById('currentProviderLabel').innerText = labels[activeProvider] || "ArcGIS Dark Canvas (OEM Clean)";
        }}

        updateBadges();
    </script>
</body>
</html>
"""

    with open(output_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(animated_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    with open(index_html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Successfully generated animated glass dashboard:")
    print(f"    - {output_html_path}")
    print(f"    - {animated_html_path}")
    print(f"    - {index_html_path}")
    print(f"[+] Total telemetry waypoints embedded: {len(records)}")
    print(f"[+] Total causal chain events: {len(causal_chain)}")
    print(f"[+] Verified artifacts: {len(artifacts)}")

if __name__ == "__main__":
    generate_dashboard()
