"""
Natural Language Processing (NLP) Forensic Text and Log Analysis Engine
Specialized for Vehicle Infotainment (IVI) and Telematics Forensic Triage.

Components:
1. Drain-Inspired Tree-Based Log Template Miner & Normalizer
2. Automotive Named Entity Recognition (Auto-NER) Engine
3. Semantic Intent & Distraction Pattern Classifier
"""

import re
from typing import Dict, List, Any

class DrainNode:
    def __init__(self, depth=0, digit_or_token=None):
        self.depth = depth
        self.digit_or_token = digit_or_token
        self.children = {}
        self.template_clusters = []

class DrainLogParser:
    """
    Implementation of the Drain fixed-depth parse tree algorithm 
    for real-time streaming log template mining.
    """
    def __init__(self, depth=4, sim_th=0.5):
        self.max_depth = depth - 2
        self.sim_th = sim_th
        self.root = DrainNode()
        self.templates = []

    def _tokenize(self, log_line: str) -> List[str]:
        # Strip timestamp headers and tokenize
        tokens = log_line.strip().split()
        return tokens

    def _has_digits(self, s: str) -> bool:
        return any(char.isdigit() for char in s)

    def _similarity(self, seq1: List[str], seq2: List[str]) -> float:
        if len(seq1) != len(seq2):
            return 0.0
        matches = sum(1 for token1, token2 in zip(seq1, seq2) if token1 == token2)
        return matches / len(seq1)

    def parse(self, log_line: str) -> Dict[str, Any]:
        tokens = self._tokenize(log_line)
        seq_len = len(tokens)
        if seq_len == 0:
            return {"template": "", "parameters": []}

        # Match or add to Drain tree
        node = self.root
        if seq_len not in node.children:
            node.children[seq_len] = DrainNode(depth=1, digit_or_token=seq_len)
        node = node.children[seq_len]

        first_token = tokens[0] if not self._has_digits(tokens[0]) else "<*VAR*>"
        if first_token not in node.children:
            node.children[first_token] = DrainNode(depth=2, digit_or_token=first_token)
        node = node.children[first_token]

        # Search existing template clusters
        matched_cluster = None
        max_sim = -1.0
        for cluster in node.template_clusters:
            sim = self._similarity(tokens, cluster["template_tokens"])
            if sim > max_sim and sim >= self.sim_th:
                max_sim = sim
                matched_cluster = cluster

        if matched_cluster is None:
            template_tokens = [
                "<*NUM*>" if self._has_digits(t) else t 
                for t in tokens
            ]
            new_cluster = {
                "cluster_id": f"TPL-{len(self.templates) + 1:03d}",
                "template_tokens": template_tokens,
                "template_str": " ".join(template_tokens),
                "count": 1
            }
            node.template_clusters.append(new_cluster)
            self.templates.append(new_cluster)
            cluster_id = new_cluster["cluster_id"]
            tpl_str = new_cluster["template_str"]
        else:
            matched_cluster["count"] += 1
            cluster_id = matched_cluster["cluster_id"]
            tpl_str = matched_cluster["template_str"]

        return {
            "template_id": cluster_id,
            "template": tpl_str,
            "raw_log": log_line
        }


class AutomotiveForensicNER:
    """
    Domain-Specific Named Entity Recognition (NER) for Automotive Telematics & IVI.
    Extracts: VIN, Coordinates, Speeds, DTCs, Phone Numbers, MACs, Driver Intents.
    """
    def __init__(self):
        self.patterns = {
            "VIN": re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b"),
            "DTC_CODE": re.compile(r"\b[B|C|P|U][0-9]{4}(?:-[0-9A-Fa-f]{2})?\b"),
            "PHONE_NUMBER": re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"),
            "MAC_ADDRESS": re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
            "GPS_LAT_LON": re.compile(r"(?:Lat|latitude)=?([+-]?\d+\.\d+)[,\s]+(?:Lon|longitude)=?([+-]?\d+\.\d+)", re.IGNORECASE),
            "SPEED_METRIC": re.compile(r"(\d+(?:\.\d+)?)\s*(?:km/h|kph|mph)", re.IGNORECASE),
            "DELTA_V": re.compile(r"Delta-V\s*(?:X=([+-]?\d+km/h))?,?\s*(?:Y=([+-]?\d+km/h))?", re.IGNORECASE),
            "CRITICAL_EVENT": re.compile(r"\b(Collision|AEB_TRIGGER|Airbag|Crash|Rollover|eCall|Impact)\b", re.IGNORECASE)
        }

    def extract_entities(self, text: str) -> Dict[str, List[Any]]:
        entities = {}
        for entity_type, regex in self.patterns.items():
            matches = regex.findall(text)
            if matches:
                # Normalize tuple matches
                flat_matches = []
                for m in matches:
                    if isinstance(m, tuple):
                        flat_matches.append([item for item in m if item])
                    else:
                        flat_matches.append(m)
                entities[entity_type] = flat_matches
        return entities


class DriverInteractionClassifier:
    """
    Semantic Intent & Distraction Classifier for Infotainment Text & Voice Queries.
    Evaluates whether an interaction indicates visual, manual, or cognitive distraction.
    """
    DISTRACTION_LEXICON = {
        "HIGH_DISTRACTION": [
            "email", "contract", "read message", "read the last", "typing", 
            "screen", "opening it now", "check your email", "urgent"
        ],
        "MEDIUM_DISTRACTION": [
            "navigate", "destination", "play", "playlist", "spotify", "music", "phone call"
        ],
        "EMERGENCY": [
            "911", "emergency", "dispatch", "ecall", "ambulance", "crash", "help"
        ]
    }

    def analyze_interaction(self, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        score = 0
        categories = []

        for kw in self.DISTRACTION_LEXICON["HIGH_DISTRACTION"]:
            if kw in text_lower:
                score += 3
                categories.append("HIGH_COGNITIVE_VISUAL_DISTRACTION")
                break

        for kw in self.DISTRACTION_LEXICON["MEDIUM_DISTRACTION"]:
            if kw in text_lower:
                score += 1
                categories.append("INFOTAINMENT_INTERACTION")
                break

        for kw in self.DISTRACTION_LEXICON["EMERGENCY"]:
            if kw in text_lower:
                score += 0
                categories.append("EMERGENCY_RESPONSE")
                break

        distraction_level = "NONE"
        if score >= 3:
            distraction_level = "CRITICAL_DISTRACTION"
        elif score >= 1:
            distraction_level = "MODERATE_DISTRACTION"

        return {
            "distraction_level": distraction_level,
            "distraction_score": score,
            "classified_tags": list(set(categories)),
            "analyzed_text": text
        }

if __name__ == "__main__":
    drain = DrainLogParser()
    ner = AutomotiveForensicNER()
    clf = DriverInteractionClassifier()

    sample_log = "oem-gateway[4012]: CRITICAL [AIRBAG_ECU] Collision detected. Delta-V X=-42km/h, Y=+8km/h. DTC B0001-13 set."
    sample_text = "Opening it now on my screen"

    print("[*] Testing Drain Log Template Mining:")
    parsed = drain.parse(sample_log)
    print(f"  Template ID: {parsed['template_id']}")
    print(f"  Template: {parsed['template']}")

    print("\n[*] Testing Automotive-NER:")
    entities = ner.extract_entities(sample_log)
    print(f"  Extracted Entities: {entities}")

    print("\n[*] Testing Driver Distraction Classification:")
    classification = clf.analyze_interaction(sample_text)
    print(f"  Result: {classification}")
