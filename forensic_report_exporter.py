"""
Forensic Report Exporter
Generates court-admissible digital forensic investigation reports adhering to
ISO/IEC 27037, NIST SP 800-86, and Federal Rules of Evidence.
Exports both structured JSON-LD and a detailed Markdown report.
"""

import json
import os
from datetime import datetime, timezone
from typing import Dict, Any

class ForensicReportExporter:
    def __init__(self, case_id: str, examiner: str, output_dir: str):
        self.case_id = case_id
        self.examiner = examiner
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_markdown_report(self, manifest_data: Dict[str, Any], correlation_data: Dict[str, Any]) -> str:
        md_lines = [
            f"# DIGITAL FORENSIC EXAMINATION REPORT",
            f"**Case Reference:** {self.case_id}  ",
            f"**Lead Examiner:** {self.examiner}  ",
            f"**Date of Report:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Governing Standards:** ISO/IEC 27037:2012, NIST SP 800-86, NIST SP 800-101 Rev.1  ",
            "\n---\n",
            "## 1. Executive Summary & Findings",
            correlation_data["forensic_conclusion"],
            "\n**Key Evidentiary Highlights:**",
            f"- **Total Events Ingested & Analyzed:** {correlation_data['total_events_processed']}",
            f"- **Driver Distraction Precursors Identified:** {len(correlation_data['distraction_findings'])} events",
            f"- **Primary Collision Timestamp:** {correlation_data['impact_event']['timestamp_utc'] if correlation_data['impact_event'] else 'N/A'}",
            "\n---\n",
            "## 2. Chain of Custody & Evidence Acquisition Manifest",
            "The following evidence files were acquired from OEM Cloud endpoints and cryptographically verified upon ingestion:",
            "\n| Artifact ID | File Name | Category | Size (Bytes) | SHA-256 Digest |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ]

        for art in manifest_data.get("acquired_artifacts", []):
            sha_short = art["integrity_verification"]["algorithm_sha256"][:16] + "..." + art["integrity_verification"]["algorithm_sha256"][-8:]
            md_lines.append(
                f"| `{art['artifact_id']}` | `{art['filename']}` | `{art['category']}` | {art['size_bytes']} | `{sha_short}` |"
            )

        md_lines.extend([
            "\n---\n",
            "## 3. High-Resolution Precursor & Incident Timeline",
            "Temporal alignment of IVI text, voice interactions, and high-frequency CAN telematics dynamics within the critical incident window (-15.0s to +5.0s relative to impact):",
            "\n| Time (UTC) | Source | Category | Dynamic Telemetry / Interaction Content | Event Status |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ])

        for entry in correlation_data.get("precursor_causal_chain", []):
            ts = entry["timestamp_utc"].replace("+00:00", "Z")
            summary = entry["summary"].replace("|", "\\|")
            tag = entry["event_tag"]
            src = entry["source"]
            cat = entry["category"]
            md_lines.append(f"| `{ts}` | `{src}` | `{cat}` | {summary} | **{tag}** |")

        md_lines.extend([
            "\n---\n",
            "## 4. NLP Text Analysis & Driver Distraction Findings",
            "Natural Language Processing (NLP) entity extraction and semantic sentiment/intent classification of user communication during transit:",
            "\n| Seconds Pre-Impact | Interaction Channel | Analyzed Text | Assessed Distraction Level |",
            "| :--- | :--- | :--- | :--- |"
        ])

        for dist in correlation_data.get("distraction_findings", []):
            md_lines.append(
                f"| `T - {dist['seconds_before_impact']}s` | `{dist['source']}` | *\"{dist['text']}\"* | **{dist['level']}** |"
            )

        md_lines.extend([
            "\n---\n",
            "## 5. Examiner Certification",
            "I hereby certify that the digital evidence items described above were preserved, acquired, analyzed, and documented in strict compliance with ISO/IEC 27037 and accepted scientific digital forensic methodologies.",
            f"\n**Digital Signature Hash:** `{manifest_data.get('acquired_artifacts', [{}])[0].get('integrity_verification', {}).get('algorithm_sha256', 'VERIFIED')}`  ",
            f"**Examiner:** {self.examiner}  ",
            f"**Date:** {datetime.now(timezone.utc).strftime('%B %d, %Y')}"
        ])

        report_content = "\n".join(md_lines)
        report_path = os.path.join(self.output_dir, "forensic_examination_report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_content)
        return report_path

    def generate_json_report(self, manifest_data: Dict[str, Any], correlation_data: Dict[str, Any]) -> str:
        report_dict = {
            "@context": "https://schema.org/DigitalDocument",
            "type": "DigitalForensicInvestigationReport",
            "case_id": self.case_id,
            "examiner": self.examiner,
            "generated_timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "chain_of_custody_manifest": manifest_data,
            "forensic_results": correlation_data
        }
        json_path = os.path.join(self.output_dir, "forensic_report.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2)
        return json_path
