"""
Main Forensic Pipeline Orchestrator
Executes the end-to-end framework:
1. Synthetic Multi-Source Connected Vehicle Generation
2. ISO/IEC 27037 Cryptographic Cloud Ingestion
3. NLP Log Template Mining & Automotive Named Entity Recognition
4. Temporal-Spatial Fusion & Precursor Incident Correlation
5. Court-Admissible Forensic Report Export
"""

import os
import json
import time
from synthetic_vehicle_data_generator import generate_evidence_environment
from cloud_acquisition_engine import CloudForensicAcquisition
from evidence_correlator import VehicularEvidenceCorrelator
from forensic_report_exporter import ForensicReportExporter
from generate_dashboard import generate_dashboard

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    raw_evidence_dir = os.path.join(base_dir, "raw_evidence_source")
    vault_dir = os.path.join(base_dir, "forensic_vault")
    reports_dir = os.path.join(base_dir, "forensic_reports")
    
    case_id = "CAS-2026-CAV-089"
    examiner = "Special Agent Forensic Investigator, DFIR Unit"

    print("=" * 80)
    print("  AUTO-FORENS-NLP: CONNECTED VEHICLE & TELEMATICS CLOUD FORENSIC SUITE")
    print("  Compliance: ISO/IEC 27037:2012 | NIST SP 800-86 | NIST SP 800-101 R1")
    print("=" * 80)

    # Step 1: Synthesize Real-World Vehicle Telematics & Infotainment Logs
    print("\n[Stage 1/5] Synthesizing Multi-Source Vehicle & Cloud Infrastructure...")
    sources = generate_evidence_environment(raw_evidence_dir)
    print(f"  [+] Telematics Telemetry: {os.path.basename(sources['telematics_json'])}")
    print(f"  [+] Infotainment SQLite:  {os.path.basename(sources['ivi_sqlite'])}")
    print(f"  [+] Gateway Syslog Dumps: {os.path.basename(sources['gateway_syslog'])}")

    # Step 2: Forensically Sound Cloud Evidence Ingestion
    print("\n[Stage 2/5] Performing Cryptographic Ingestion & Evidence Sealing...")
    acq = CloudForensicAcquisition(case_id=case_id, examiner=examiner, secure_vault_dir=vault_dir)
    acq.acquire_artifact(sources["telematics_json"], "OEM_TELEMATICS_STREAM", "https://fleet.autocloud.net/v2/telemetry/archive")
    acq.acquire_artifact(sources["ivi_sqlite"], "IVI_COMPANION_CACHE", "https://sync.autocloud.net/v1/user_sync/storage.db")
    acq.acquire_artifact(sources["gateway_syslog"], "CLOUD_GATEWAY_SYSLOG", "syslog://oem-gateway-us-west.cloud.internal:514")
    manifest_file = acq.finalize_acquisition()
    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest_data = json.load(f)
    print(f"  [+] Manifest generated with {len(manifest_data['acquired_artifacts'])} sealed artifacts.")
    print(f"  [+] Primary SHA-256 Digest: {manifest_data['acquired_artifacts'][0]['integrity_verification']['algorithm_sha256'][:24]}...")

    # Step 3 & 4: NLP Parsing & Multi-Modal Temporal Correlation
    print("\n[Stage 3/5 & 4/5] Running NLP Template Mining, Auto-NER, & Temporal-Spatial Fusion...")
    correlator = VehicularEvidenceCorrelator(vault_dir)
    correlator.load_telematics()
    correlator.load_ivi_database()
    correlator.load_gateway_syslog()
    correlation_results = correlator.correlate_incident_window()

    print(f"  [+] Ingested Events: {correlation_results['total_events_processed']}")
    print(f"  [+] Critical Incident Window Events: {len(correlation_results['precursor_causal_chain'])}")
    print(f"  [+] Identified Distraction Precursors: {len(correlation_results['distraction_findings'])}")

    # Step 5: Exporting Court-Admissible Reports
    print("\n[Stage 5/5] Generating Forensic Examination Documentation...")
    exporter = ForensicReportExporter(case_id=case_id, examiner=examiner, output_dir=reports_dir)
    md_report = exporter.generate_markdown_report(manifest_data, correlation_results)
    json_report = exporter.generate_json_report(manifest_data, correlation_results)
    dashboard_path = generate_dashboard()

    print(f"  [+] Markdown Report:    {os.path.basename(md_report)}")
    print(f"  [+] JSON-LD Evidence:   {os.path.basename(json_report)}")
    print(f"  [+] Visual Dashboard:   {os.path.basename(dashboard_path)}")

    print("\n" + "=" * 80)
    print("  EXAMINER FINDINGS & CAUSAL EVIDENCE SUMMARY")
    print("=" * 80)
    print(f"CONCLUSION: {correlation_results['forensic_conclusion']}\n")
    print("Pre-Impact Distraction Timeline:")
    for d in correlation_results["distraction_findings"]:
        print(f"  • [T - {d['seconds_before_impact']:4.1f}s] [{d['level']}] '{d['text']}' via {d['source']}")
    
    print("\nPrimary Impact Point:")
    impact = correlation_results["impact_event"]
    if impact:
        print(f"  • Timestamp: {impact['timestamp_utc']}")
        print(f"  • Event Tag: {impact['event_tag']}")
        print(f"  • Telemetry: {impact['summary']}")
    print("=" * 80)

if __name__ == "__main__":
    main()
