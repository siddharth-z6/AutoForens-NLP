# AutoForens-NLP: Cloud Storage Forensic Evidence Acquisition via NLP for Telematics and IVI Analysis

[![Compliance](https://img.shields.io/badge/Compliance-ISO%2FIEC%2027037%20%7C%20NIST%20SP%20800--101%20R1-blue.svg)]()
[![Python](https://img.shields.io/badge/Python-3.10%2B-green.svg)]()
[![LaTeX](https://img.shields.io/badge/LaTeX-IEEE%20Transactions-red.svg)]()

A digital forensics framework for acquiring and analyzing connected vehicle cloud storage repositories, In-Vehicle Infotainment (IVI) mirrors, and Telematics Control Unit (TCU) log streams using Natural Language Processing (NLP).

---

## 1. Directory Structure

```
Digital forensics/
├── run_forensic_pipeline.py            # End-to-end execution script
├── synthetic_vehicle_data_generator.py # Simulates multi-source CAV telemetry & IVI databases
├── cloud_acquisition_engine.py         # ISO/IEC 27037 cryptographically sealed cloud ingestion
├── nlp_forensic_analyzer.py            # Drain-based log template miner, Auto-NER, & classifier
├── evidence_correlator.py              # Temporal-spatial fusion of text, voice, and vehicle dynamics
├── can_telematics_parser.py            # Raw CAN arbitration ID decoding & OpenXC trace parser
├── forensic_report_exporter.py         # Court-admissible Markdown & JSON-LD report generator
├── dashboard.html                      # Standalone interactive Leaflet + Chart.js forensic UI
├── serve_dashboard.py                  # Local lightweight HTTP server for the dashboard
│
├── latex_paper/                        # Publication-ready IEEE conference manuscript
│   ├── paper.tex                       # IEEEtran two-column paper source
│   └── references.bib                  # BibTeX academic citations (ISO, NIST, Drain, IVI)
│
├── raw_evidence_source/                # Unprocessed mock vehicle cloud & IVI evidence
│   ├── cloud_telematics_stream.json    # OEM high-frequency CAN telematics (speed, brake, DTCs)
│   ├── ivi_companion_sync.sqlite       # Infotainment SMS, voice commands, calls, and BLE pairs
│   ├── raw_cloud_gateway.log           # Unstructured OEM cloud server syslogs
│   └── openxc_sample_trace.json        # OpenXC connected vehicle streaming telemetry
│
├── forensic_vault/                     # Immutable evidence vault with SHA-256 seals
│   ├── acquisition_manifest.json       # Formal chain of custody ledger
│   └── manifest_seal.sha256            # Cryptographic hash digest of manifest
│
└── forensic_reports/                   # Generated investigative findings
    ├── forensic_examination_report.md  # Detailed forensic narrative with timeline table
    └── forensic_report.json            # Structured machine-readable JSON-LD evidence graph
```

---

## 2. Key Capabilities & Forensic Workflow

1. **Cryptographically Sound Cloud Ingestion (ISO/IEC 27037):**
   - Simulates cloud API endpoints (e.g., AWS IoT FleetWise, Azure Connected Vehicle, OEM portals).
   - Verifies bit-stream integrity using dual-hash verification (SHA-256 & SHA-512).
   - Generates an immutable, non-repudiable acquisition manifest (`acquisition_manifest.json`).

2. **Domain-Specific NLP & Log Mining:**
   - **Drain Algorithm:** Tree-based online log template miner that decouples static system templates from dynamic variables.
   - **Automotive-NER:** Recognizes VINs, Diagnostic Trouble Codes (DTCs), GPS waypoints, speeds, Delta-V impact metrics, phone numbers, and MAC addresses.
   - **Driver Distraction Classification:** Semantically categorizes text and voice queries into distraction risk tiers (visual, manual, and cognitive distraction).

3. **CAN Bus & OpenXC Decoding:**
   - Decodes raw CAN arbitration IDs (`0x130` Steering, `0x244` Speed/Gear, `0x320` Brake/Throttle, `0x020` Airbag/SRS, `0x480` DTCs) using DBC-like bit shifting and scaling.
   - Parses streaming OpenXC trace JSON files directly into normalized telemetry.

4. **Multi-Modal Temporal-Spatial Evidence Correlation:**
   - Merges asynchronous timestamps into a single timeline.
   - Reconstructs the pre-collision window ($-15$s to $+5$s) to establish cause and driver intent.
   - Accurately highlights distracted driving actions directly preceding emergency braking and airbag deployment.

5. **Interactive Forensic Dashboard:**
   - Interactive Leaflet.js map with color-coded GPS trajectory and pulsing collision marker.
   - Chart.js telemetry curve showing speed, brake pedal %, throttle %, and annotated interaction callouts.
   - Drain template miner and Auto-NER entity inspector.

---

## 3. How to Run

### Run the Forensic Analysis Pipeline
```powershell
py run_forensic_pipeline.py
```

### Test CAN Bus & OpenXC Parser
```powershell
py can_telematics_parser.py
```

### Launch Interactive Visual Dashboard
```powershell
py serve_dashboard.py
```
*Or directly open [dashboard.html](file:///c:/Users/RAVI%20KIRAN/OneDrive/Desktop/Digital%20forensics/dashboard.html) in your browser.*

---

## 4. Academic Paper & Forensic Catalog Links
- Manuscript Source: [paper.tex](file:///c:/Users/RAVI%20KIRAN/OneDrive/Desktop/Digital%20forensics/latex_paper/paper.tex)
- BibTeX References: [references.bib](file:///c:/Users/RAVI%20KIRAN/OneDrive/Desktop/Digital%20forensics/latex_paper/references.bib)
- Examination Report: [forensic_examination_report.md](file:///c:/Users/RAVI%20KIRAN/OneDrive/Desktop/Digital%20forensics/forensic_reports/forensic_examination_report.md)
