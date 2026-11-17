"""
Generator for standalone forensic_map.html
Creates a full-screen, high-performance, watermark-free forensic GIS reconstruction map.
"""

import json
import os

def create_forensic_map():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    telematics_path = os.path.join(base_dir, "forensic_vault", "cloud_telematics_stream.json")
    report_path = os.path.join(base_dir, "forensic_reports", "forensic_report.json")
    output_path = os.path.join(base_dir, "forensic_map.html")

    with open(telematics_path, "r", encoding="utf-8") as f:
        telematics_data = json.load(f)

    with open(report_path, "r", encoding="utf-8") as f:
        report_data = json.load(f)

    records = telematics_data.get("telemetry_records", [])
    causal_chain = report_data.get("forensic_results", {}).get("precursor_causal_chain", [])
    distractions = report_data.get("forensic_results", {}).get("distraction_findings", [])
    impact = report_data.get("forensic_results", {}).get("impact_event", {})

    crash_lat = 37.78015
    crash_lon = -122.4152
    if impact and "details" in impact and "gps" in impact["details"]:
        crash_lat = impact["details"]["gps"].get("latitude", crash_lat)
        crash_lon = impact["details"]["gps"].get("longitude", crash_lon)

    records_json = json.dumps(records)
    causal_chain_json = json.dumps(causal_chain)
    distractions_json = json.dumps(distractions)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AutoForens-NLP | Forensic GIS & Crash Reconstruction Map</title>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Leaflet CSS & JS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        body, html {{
            height: 100%;
            margin: 0;
            padding: 0;
            overflow: hidden;
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background-color: #030712;
            color: #f3f4f6;
        }}
        .font-mono {{
            font-family: 'JetBrains Mono', monospace;
        }}
        #map {{
            height: 100vh;
            width: 100vw;
            z-index: 1;
            background-color: #030712;
        }}
        .leaflet-dark-tiles {{
            filter: brightness(0.6) invert(1) contrast(3) hue-rotate(200deg) saturate(0.3) brightness(0.7) !important;
        }}
        .pulsing-marker {{
            width: 26px;
            height: 26px;
            background: #ef4444;
            border-radius: 50%;
            border: 3px solid #ffffff;
            box-shadow: 0 0 0 rgba(239, 68, 68, 0.7);
            animation: pulse-ring 1.3s infinite;
        }}
        @keyframes pulse-ring {{
            0% {{
                transform: scale(0.9);
                box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.85);
            }}
            70% {{
                transform: scale(1.15);
                box-shadow: 0 0 0 20px rgba(239, 68, 68, 0);
            }}
            100% {{
                transform: scale(0.9);
                box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
            }}
        }}
        .custom-popup .leaflet-popup-content-wrapper {{
            background: #0f172a;
            color: #e2e8f0;
            border: 1px solid #334155;
            border-radius: 0.75rem;
            padding: 4px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.6);
        }}
        .custom-popup .leaflet-popup-tip {{
            background: #0f172a;
        }}
        /* Custom scrollbar */
        ::-webkit-scrollbar {{
            width: 6px;
        }}
        ::-webkit-scrollbar-track {{
            background: #0b0f19;
        }}
        ::-webkit-scrollbar-thumb {{
            background: #1e293b;
            border-radius: 4px;
        }}
    </style>
</head>
<body class="relative">

    <!-- Top Navigation Header -->
    <header class="absolute top-0 left-0 right-0 z-30 bg-slate-950/85 backdrop-blur-md border-b border-slate-800/80 px-4 py-2.5 flex items-center justify-between shadow-2xl">
        <div class="flex items-center gap-3">
            <a href="dashboard.html" class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-700/80 hover:bg-slate-800 text-slate-300 hover:text-white text-xs font-mono transition">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"></path></svg>
                Full Dashboard
            </a>
            <div class="h-4 w-px bg-slate-800"></div>
            <div class="flex items-center gap-2">
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
                <h1 class="text-sm font-bold text-white tracking-wide">AutoForens-NLP</h1>
                <span class="text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 px-2 py-0.5 rounded font-mono">GIS Reconstruction</span>
            </div>
            <span class="hidden md:inline-block text-xs text-slate-400 font-mono">| CASE CAS-2026-CAV-089 &bull; VIN 1G1YY22U965104928</span>
        </div>

        <div class="flex items-center gap-2">
            <!-- Active Layer Indicator -->
            <div class="hidden sm:flex items-center gap-1.5 bg-slate-900/90 border border-slate-800 px-3 py-1 rounded-lg text-xs font-mono">
                <span class="text-slate-400">Map Layer:</span>
                <span id="activeLayerLabel" class="text-emerald-400 font-semibold">ArcGIS Dark Canvas</span>
            </div>

            <!-- Quick Action Buttons -->
            <button onclick="fitMapBounds()" class="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-200 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer">
                <svg class="w-3.5 h-3.5 text-sky-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 8V4m0 0h4M4 4l5 5m11-1V4m0 0h-4m4 0l-5 5M4 16v4m0 0h4m-4 0l5-5m11 5l-5-5m5 5v-4m0 4h-4"></path></svg>
                Fit Track
            </button>
            <button onclick="zoomToCrash()" class="px-3 py-1.5 rounded-lg bg-rose-950/80 border border-rose-800 hover:bg-rose-900 text-rose-200 text-xs font-mono transition flex items-center gap-1.5 cursor-pointer">
                <svg class="w-3.5 h-3.5 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path></svg>
                Impact Site
            </button>
        </div>
    </header>

    <!-- Floating Telemetry HUD (Top Left) -->
    <aside class="absolute top-16 left-4 z-20 w-80 bg-slate-950/90 backdrop-blur-md border border-slate-800 rounded-xl p-4 shadow-2xl space-y-3 pointer-events-auto">
        <div class="flex justify-between items-center border-b border-slate-800/80 pb-2">
            <span class="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-1.5">
                <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
                Live Dynamics HUD
            </span>
            <span id="hudSimTime" class="text-xs font-mono text-amber-400 font-semibold">T + 00.0s</span>
        </div>

        <!-- Telemetry Gauges Grid -->
        <div class="grid grid-cols-2 gap-2 text-xs font-mono">
            <div class="bg-slate-900/80 border border-slate-800/90 rounded-lg p-2.5">
                <div class="text-[10px] text-slate-400 uppercase">Speed</div>
                <div class="text-lg font-bold text-emerald-400" id="hudSpeed">65.0 <span class="text-xs text-slate-400">mph</span></div>
                <div class="text-[10px] text-slate-500" id="hudSpeedKph">104.6 km/h</div>
            </div>
            <div class="bg-slate-900/80 border border-slate-800/90 rounded-lg p-2.5">
                <div class="text-[10px] text-slate-400 uppercase">Brake Boost</div>
                <div class="text-lg font-bold text-sky-400" id="hudBrake">0.0 <span class="text-xs text-slate-400">%</span></div>
                <div class="text-[10px] text-slate-500" id="hudBrakeStatus">Cruise / Inactive</div>
            </div>
            <div class="bg-slate-900/80 border border-slate-800/90 rounded-lg p-2.5">
                <div class="text-[10px] text-slate-400 uppercase">Throttle</div>
                <div class="text-base font-bold text-amber-400" id="hudThrottle">28.0%</div>
                <div class="text-[10px] text-slate-500">Gear: <span id="hudGear" class="text-slate-300">D</span></div>
            </div>
            <div class="bg-slate-900/80 border border-slate-800/90 rounded-lg p-2.5">
                <div class="text-[10px] text-slate-400 uppercase">Steering Angle</div>
                <div class="text-base font-bold text-indigo-300" id="hudSteering">0.5&deg;</div>
                <div class="text-[10px] text-slate-500">Heading: <span id="hudHeading">42.1&deg;</span></div>
            </div>
        </div>

        <!-- GPS Coordinates -->
        <div class="bg-slate-900/60 border border-slate-800/80 rounded-lg p-2 text-[11px] font-mono space-y-1">
            <div class="flex justify-between">
                <span class="text-slate-400">GNSS Fix:</span>
                <span class="text-slate-200" id="hudCoords">37.77490, -122.41940</span>
            </div>
            <div class="flex justify-between">
                <span class="text-slate-400">Event Status:</span>
                <span class="text-emerald-400 font-semibold truncate max-w-[170px]" id="hudEventTag">NORMAL_CRUISE</span>
            </div>
        </div>

        <!-- Dynamic Distraction Callout -->
        <div id="hudDistractionBox" class="bg-amber-950/40 border border-amber-800/80 rounded-lg p-2 text-xs hidden">
            <div class="flex items-center gap-1.5 text-amber-400 font-bold text-[11px] mb-1">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path></svg>
                DRIVER DISTRACTION DETECTED
            </div>
            <p id="hudDistractionText" class="text-amber-200 text-[11px] italic font-mono"></p>
        </div>
    </aside>

    <!-- Map Canvas Element (Zero Watermark) -->
    <main id="map"></main>

    <!-- Bottom Timeline & Scrubber Bar -->
    <footer class="absolute bottom-4 left-4 right-4 z-20 max-w-4xl mx-auto bg-slate-950/90 backdrop-blur-md border border-slate-800 rounded-2xl p-4 shadow-2xl space-y-3 pointer-events-auto">
        <div class="flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
            <div class="flex items-center gap-2">
                <button id="playBtn" onclick="toggleTrajectoryPlay()" class="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-semibold flex items-center gap-2 cursor-pointer transition shadow-lg shadow-indigo-600/30">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <span id="playBtnText">Replay Track</span>
                </button>
                <button onclick="stepTrajectory(-1)" class="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg cursor-pointer transition" title="Step -1s">&larr;</button>
                <button onclick="stepTrajectory(1)" class="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg cursor-pointer transition" title="Step +1s">&rarr;</button>
                <button onclick="resetTrajectoryPlay()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg cursor-pointer transition">Reset</button>
            </div>

            <div class="flex items-center gap-3">
                <span class="text-slate-400">Playback Speed:</span>
                <select id="playSpeedSelect" onchange="changePlaySpeed()" class="bg-slate-900 border border-slate-700 rounded px-2.5 py-1 text-xs text-white focus:outline-none">
                    <option value="0.5">0.5x</option>
                    <option value="1.0" selected>1.0x (Realtime)</option>
                    <option value="2.0">2.0x</option>
                    <option value="4.0">4.0x</option>
                </select>
                <div class="h-4 w-px bg-slate-800"></div>
                <div class="flex items-center gap-2">
                    <span class="text-slate-400">Position:</span>
                    <span id="timelineTimestamp" class="text-amber-400 font-bold">23:45:00 UTC</span>
                </div>
            </div>
        </div>

        <!-- Scrubber Slider -->
        <div class="space-y-1">
            <input type="range" id="trajectorySlider" min="0" max="{len(records) - 1}" value="0" oninput="scrubTrajectory(this.value)" class="w-full accent-indigo-500 cursor-pointer h-2 bg-slate-800 rounded-lg">
            <div class="flex justify-between text-[10px] text-slate-400 font-mono">
                <span class="text-emerald-400">T=00s (Trip Start)</span>
                <span class="text-amber-400">T=24s (Inbound SMS)</span>
                <span class="text-purple-400">T=27s (Voice Query)</span>
                <span class="text-sky-400">T=32s (AEB Brake)</span>
                <span class="text-rose-400 font-bold">T=35s (CRASH &amp; AIRBAG)</span>
                <span class="text-slate-500">T=59s (PSAP eCall)</span>
            </div>
        </div>
    </footer>

    <!-- Leaflet & Telemetry Core Application Logic -->
    <script>
        // Embedded High-Frequency Vehicle Telematics Records
        const trackData = {records_json};
        const causalEvents = {causal_chain_json};
        const distractionEvents = {distractions_json};
        const crashCenter = [{crash_lat}, {crash_lon}];

        const waypoints = trackData.map(d => [d.gps.latitude, d.gps.longitude]);

        // 1. Initialize Map
        const map = L.map('map', {{
            zoomControl: false,
            center: crashCenter,
            zoom: 15
        }});

        L.control.zoom({{ position: 'topright' }}).addTo(map);
        L.control.scale({{ imperial: true, metric: true, position: 'bottomright' }}).addTo(map);

        // 2. High-Performance Tile Providers (Zero API Key Required & Zero Watermarks)
        const baseMaps = {{
            "ArcGIS Dark Canvas (Default)": L.layerGroup([
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
            "Google Maps Hybrid": L.tileLayer('https://mt1.google.com/vt/lyrs=y&x={{z}}&y={{y}}&z={{z}}', {{
                maxZoom: 20,
                attribution: '&copy; Google Maps'
            }})
        }};

        // Add Default Zero-Watermark Layer
        baseMaps["ArcGIS Dark Canvas (Default)"].addTo(map);
        const layersControl = L.control.layers(baseMaps, null, {{ position: 'topright' }}).addTo(map);

        map.on('baselayerchange', function(e) {{
            document.getElementById('activeLayerLabel').innerText = e.name;
        }});

        // 3. Render High-Contrast Polyline Trajectory Segments
        // Normal Cruise (T=0 to T=24) - Emerald Green
        L.polyline(waypoints.slice(0, 26), {{
            color: '#10b981',
            weight: 5.5,
            opacity: 0.95,
            lineJoin: 'round'
        }}).addTo(map).bindPopup("<b>Phase 1: Normal Cruise (T=0 to T=24s)</b><br>Speed: 65 mph &bull; Driver Attentive");

        // Distraction & Lane Departure (T=25 to T=31) - Amber Dashed
        L.polyline(waypoints.slice(24, 33), {{
            color: '#f59e0b',
            weight: 6,
            dashArray: '8, 8',
            opacity: 1.0,
            lineJoin: 'round'
        }}).addTo(map).bindPopup("<b>Phase 2: Distraction &amp; Lane Departure (T=25 to T=31s)</b><br>Inbound SMS + Voice query + Typing on screen");

        // AEB Emergency Braking (T=32 to T=35) - Sky Blue
        L.polyline(waypoints.slice(31, 36), {{
            color: '#38bdf8',
            weight: 6.5,
            opacity: 1.0,
            lineJoin: 'round'
        }}).addTo(map).bindPopup("<b>Phase 3: Emergency AEB (T=32 to T=35s)</b><br>Brake boost 85% &bull; Deceleration from 58 to 18 mph");

        // Post-Crash Stopped Track (T=35 to T=59) - Red
        L.polyline(waypoints.slice(35), {{
            color: '#ef4444',
            weight: 5,
            opacity: 0.8
        }}).addTo(map).bindPopup("<b>Phase 4: Post-Impact Disabled Position</b><br>Airbag deployed &bull; Vehicle stopped");

        // 4. Milestone Markers with Forensics Callouts
        // Trip Start
        L.circleMarker(waypoints[0], {{ radius: 7, color: '#10b981', fillColor: '#10b981', fillOpacity: 1, weight: 2 }})
            .addTo(map).bindPopup("<b>Trip Start Point (T + 00s)</b><br>23:45:00 UTC<br>Speed: 65.0 mph &bull; Cruise Active");

        // T+24s: Incoming SMS
        L.circleMarker(waypoints[24], {{ radius: 7, color: '#f59e0b', fillColor: '#f59e0b', fillOpacity: 1, weight: 2 }})
            .addTo(map).bindPopup("<b>T + 24s: Inbound SMS (T - 11.0s)</b><br>From: Sarah Miller<br><em>'Urgent: Check your email right now...'</em>");

        // T+27s: Voice Assistant Trigger
        L.circleMarker(waypoints[27], {{ radius: 7, color: '#a855f7', fillColor: '#a855f7', fillOpacity: 1, weight: 2 }})
            .addTo(map).bindPopup("<b>T + 27s: IVI Voice Query (T - 8.0s)</b><br>Query: <em>'Read the last incoming message from Sarah'</em>");

        // T+29s: Outbound SMS Compose
        L.circleMarker(waypoints[29], {{ radius: 7, color: '#ec4899', fillColor: '#ec4899', fillOpacity: 1, weight: 2 }})
            .addTo(map).bindPopup("<b>T + 29s: Driver Texting (T - 6.0s)</b><br>Sent: <em>'Opening it now on my screen'</em><br>High Visual/Manual Distraction");

        // T+32s: AEB Trigger
        L.circleMarker(waypoints[32], {{ radius: 7, color: '#38bdf8', fillColor: '#38bdf8', fillOpacity: 1, weight: 2 }})
            .addTo(map).bindPopup("<b>T + 32s: Hydraulic AEB Boost (T - 3.0s)</b><br>Brake boost: 85% &bull; Deceleration initiated");

        // Collision Epicenter Pulsing Marker
        const pulsingIcon = L.divIcon({{
            className: 'pulsing-marker',
            iconSize: [26, 26],
            iconAnchor: [13, 13]
        }});
        L.marker(crashCenter, {{ icon: pulsingIcon }}).addTo(map).bindPopup(`
            <div class="p-1 font-mono text-xs">
                <div class="text-rose-400 font-bold flex items-center gap-1 mb-1">
                    <span class="w-2 h-2 rounded-full bg-rose-500 animate-ping"></span>
                    PRIMARY COLLISION SITE (T + 35s)
                </div>
                <div><strong>Timestamp:</strong> 23:45:35 UTC</div>
                <div><strong>Coordinates:</strong> 37.78015, -122.41520</div>
                <div><strong>Delta-V:</strong> X = -42 km/h, Y = +8 km/h</div>
                <div class="text-amber-300"><strong>DTC Fault:</strong> B0001-13 (Airbag Deployed)</div>
            </div>
        `);

        // 90m Forensic Exclusion Geofence
        L.circle(crashCenter, {{
            radius: 90,
            color: '#ef4444',
            fillColor: '#ef4444',
            fillOpacity: 0.14,
            dashArray: '6, 6',
            weight: 2
        }}).addTo(map).bindPopup("<b>Forensic Exclusion Perimeter</b><br>Radius: 90 meters &bull; Scene Secured");

        // 5. Dynamic Vehicle Marker
        const carIcon = L.divIcon({{
            html: '<div class="w-8 h-8 rounded-full bg-indigo-600 border-2 border-white flex items-center justify-center text-white shadow-lg shadow-indigo-600/50"><svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path d="M8 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0zM15 16.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z"></path><path d="M3 4a1 1 0 00-1 1v10a1 1 0 001 1h1.05a2.5 2.5 0 014.9 0H10a1 1 0 001-1V5a1 1 0 00-1-1H3zM14 7a1 1 0 00-1 1v6.05A2.5 2.5 0 0115.95 16H17a1 1 0 001-1v-5a1 1 0 00-.293-.707l-2-2A1 1 0 0015 7h-1z"></path></svg></div>',
            className: '',
            iconSize: [32, 32],
            iconAnchor: [16, 16]
        }});

        let vehicleMarker = L.marker(waypoints[0], {{ icon: carIcon, zIndexOffset: 1000 }}).addTo(map);

        // 6. Navigation Controls
        function fitMapBounds() {{
            map.fitBounds(L.polyline(waypoints).getBounds(), {{ padding: [60, 60] }});
        }}

        function zoomToCrash() {{
            map.flyTo(crashCenter, 18, {{ duration: 1.2 }});
        }}

        // 7. Interactive Trajectory Playback Engine
        let currentStep = 0;
        let playInterval = null;
        let speedMultiplier = 1.0;

        function setSimulationStep(idx) {{
            const pt = trackData[idx];
            if (!pt) return;

            // Move vehicle marker
            vehicleMarker.setLatLng([pt.gps.latitude, pt.gps.longitude]);

            // Update HUD
            document.getElementById('hudSimTime').innerText = `T + ${{idx < 10 ? '0' + idx : idx}}.0s`;
            document.getElementById('hudSpeed').innerHTML = `${{pt.dynamics.speed_mph.toFixed(1)}} <span class="text-xs text-slate-400">mph</span>`;
            document.getElementById('hudSpeedKph').innerText = `${{pt.dynamics.speed_kph.toFixed(1)}} km/h`;
            document.getElementById('hudBrake').innerHTML = `${{pt.dynamics.brake_pedal_pct.toFixed(1)}} <span class="text-xs text-slate-400">%</span>`;
            document.getElementById('hudBrakeStatus').innerText = pt.dynamics.brake_pedal_pct > 50 ? "AEB ACTIVE" : (pt.dynamics.brake_pedal_pct > 0 ? "Braking" : "Cruise / Inactive");
            document.getElementById('hudThrottle').innerText = `${{pt.dynamics.throttle_pct.toFixed(1)}}%`;
            document.getElementById('hudGear').innerText = pt.dynamics.gear_position;
            document.getElementById('hudSteering').innerHTML = `${{pt.dynamics.steering_angle_deg.toFixed(1)}}&deg;`;
            document.getElementById('hudHeading').innerText = `${{pt.gps.heading.toFixed(1)}}&deg;`;
            document.getElementById('hudCoords').innerText = `${{pt.gps.latitude.toFixed(5)}}, ${{pt.gps.longitude.toFixed(5)}}`;
            document.getElementById('hudEventTag').innerText = pt.event_tag;

            // Distraction Callout sync
            const distractionBox = document.getElementById('hudDistractionBox');
            const distractionText = document.getElementById('hudDistractionText');
            if (idx === 24) {{
                distractionBox.classList.remove('hidden');
                distractionText.innerText = "T+24s: Incoming SMS - 'Urgent: Check your email right now, the deal contract arrived!'";
            }} else if (idx === 27) {{
                distractionBox.classList.remove('hidden');
                distractionText.innerText = "T+27s: Voice Query - 'Read the last incoming message from Sarah'";
            }} else if (idx === 29) {{
                distractionBox.classList.remove('hidden');
                distractionText.innerText = "T+29s: Driver Texting - 'Opening it now on my screen' (Fatal cognitive diversion)";
            }} else if (idx >= 35) {{
                distractionBox.classList.remove('hidden');
                distractionBox.className = "bg-rose-950/60 border border-rose-800 rounded-lg p-2 text-xs";
                distractionText.innerHTML = "<strong class='text-rose-400'>CRASH:</strong> Airbag Deployed &bull; Delta-V -42km/h &bull; DTC B0001-13 Set";
            }} else {{
                distractionBox.classList.add('hidden');
            }}

            // Scrubber
            document.getElementById('trajectorySlider').value = idx;
            document.getElementById('timelineTimestamp').innerText = pt.timestamp.split("T")[1].replace("Z", " UTC");
        }}

        function toggleTrajectoryPlay() {{
            if (playInterval) {{
                pauseTrajectory();
            }} else {{
                startTrajectory();
            }}
        }}

        function startTrajectory() {{
            document.getElementById('playBtnText').innerText = "Pause";
            document.getElementById('playBtn').classList.replace("bg-indigo-600", "bg-amber-600");
            document.getElementById('playBtn').classList.replace("hover:bg-indigo-500", "hover:bg-amber-500");

            const intervalMs = Math.max(60, Math.floor(350 / speedMultiplier));
            playInterval = setInterval(() => {{
                if (currentStep >= trackData.length) {{
                    pauseTrajectory();
                    return;
                }}
                setSimulationStep(currentStep);
                currentStep++;
            }}, intervalMs);
        }}

        function pauseTrajectory() {{
            clearInterval(playInterval);
            playInterval = null;
            document.getElementById('playBtnText').innerText = "Replay Track";
            document.getElementById('playBtn').classList.replace("bg-amber-600", "bg-indigo-600");
            document.getElementById('playBtn').classList.replace("hover:bg-amber-500", "hover:bg-indigo-500");
        }}

        function resetTrajectoryPlay() {{
            pauseTrajectory();
            currentStep = 0;
            setSimulationStep(0);
            map.panTo(waypoints[0]);
        }}

        function stepTrajectory(delta) {{
            pauseTrajectory();
            let newStep = currentStep + delta;
            if (newStep < 0) newStep = 0;
            if (newStep >= trackData.length) newStep = trackData.length - 1;
            currentStep = newStep;
            setSimulationStep(currentStep);
        }}

        function scrubTrajectory(val) {{
            pauseTrajectory();
            currentStep = parseInt(val, 10);
            setSimulationStep(currentStep);
        }}

        function changePlaySpeed() {{
            speedMultiplier = parseFloat(document.getElementById('playSpeedSelect').value);
            if (playInterval) {{
                pauseTrajectory();
                startTrajectory();
            }}
        }}

        // Initialize at Step 0
        setSimulationStep(0);
        fitMapBounds();
    </script>
</body>
</html>
"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Successfully generated standalone forensic map: {output_path}")

if __name__ == "__main__":
    create_forensic_map()
