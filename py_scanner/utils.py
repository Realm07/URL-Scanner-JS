# py_scanner/utils.py

import re
import json
import math
import csv
from pathlib import Path
from typing import List, Dict, Any

def sanitize_filename(url: str) -> str:
    """
    converts a url into a safe filename.
    windows has a 260 char path limit and hates special chars like ':',
    so we have to be aggressive here.
    """
    # remove protocol
    sanitized = re.sub(r'https?://', '', url)
    # replace invalid chars
    sanitized = re.sub(r'[\\/*?:"<>|]', '_', sanitized)
    # truncate
    return (sanitized[:150] + '...') if len(sanitized) > 150 else sanitized

def shannon_entropy(data: str) -> float:
    """
    calculates the shannon entropy of a string.
    in plain english: it measures how "random" the string is.
    'aaaaa' has low entropy. '8f7d2a1' has high entropy.
    we use this to find api keys that don't match a specific regex.
    """
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
    loads chromium autofill patterns, filtering for 'en' (english) only.
    returns a list of compiled regex objects with metadata.
    """
    compiled_rules = []
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        for field_type, languages in data.items():
            # skip comments or metadata keys
            if not isinstance(languages, dict):
                continue
                
            # we only care about english patterns
            if 'en' in languages:
                for rule in languages['en']:
                    pattern_str = rule.get('positive_pattern')
                    if pattern_str:
                        try:
                            # chromium regexes are case-insensitive usually.
                            # we use re.ignorecase to be lenient.
                            regex = re.compile(pattern_str, re.IGNORECASE)
                            compiled_rules.append({
                                "field_type": field_type, # e.g., ADDRESS_HOME_APT_NUM
                                "regex": regex,
                                "score": rule.get('positive_score', 1.0)
                            })
                        except re.error:
                            # some regexes might be c++ specific and fail in python
                            pass
                            
    except Exception as e:
        print(f"[WARN] Could not load Chromium patterns: {e}")
        
    return compiled_rules

def save_findings_to_csv(findings: List[Dict[str, Any]], output_path: Path):
    """
    saves findings to csv.
    csv is ugly, but everyone loves opening things in excel.
    """
    if not findings:
        print("[INFO] No findings to save.")
        return

    # dynamically get headers, ensuring we capture all possible keys
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