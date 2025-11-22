# py_scanner/utils.py

import re
import json
import math
import csv
from pathlib import Path
from typing import List, Dict, Any

def sanitize_filename(url: str) -> str:
    """Converts a URL into a safe filename."""
    # Remove protocol
    sanitized = re.sub(r'https?://', '', url)
    # Replace invalid chars
    sanitized = re.sub(r'[\\/*?:"<>|]', '_', sanitized)
    # Truncate
    return (sanitized[:150] + '...') if len(sanitized) > 150 else sanitized

def shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for char_code in range(256):
        prob = float(data.count(chr(char_code))) / len(data)
        if prob > 0:
            entropy += -prob * math.log(prob, 2)
    return entropy

def load_chromium_patterns(json_path: Path) -> List[Dict]:
    """
    Loads Chromium autofill patterns, filtering for 'en' (English) only.
    Returns a list of compiled regex objects with metadata.
    """
    compiled_rules = []
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for field_type, languages in data.items():
            # Skip comments or metadata keys
            if not isinstance(languages, dict):
                continue
                
            # We only care about English patterns
            if 'en' in languages:
                for rule in languages['en']:
                    pattern_str = rule.get('positive_pattern')
                    if pattern_str:
                        try:
                            # Chromium regexes are case-insensitive usually.
                            # We use re.IGNORECASE to be lenient.
                            regex = re.compile(pattern_str, re.IGNORECASE)
                            compiled_rules.append({
                                "field_type": field_type, # e.g., ADDRESS_HOME_APT_NUM
                                "regex": regex,
                                "score": rule.get('positive_score', 1.0)
                            })
                        except re.error:
                            # Some regexes might be C++ specific and fail in Python
                            pass
                            
    except Exception as e:
        print(f"[WARN] Could not load Chromium patterns: {e}")
        
    return compiled_rules

def save_findings_to_csv(findings: List[Dict[str, Any]], output_path: Path):
    """Saves findings to CSV."""
    if not findings:
        print("[INFO] No findings to save.")
        return

    # Dynamically get headers, ensuring we capture all possible keys
    headers = set()
    for f in findings:
        headers.update(f.keys())
    
    fieldnames = sorted(list(headers))

    try:
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
        print(f"[SUCCESS] Successfully saved {len(findings)} findings to {output_path}")
    except IOError as e:
        print(f"[ERROR] Could not write to CSV file {output_path}: {e}")