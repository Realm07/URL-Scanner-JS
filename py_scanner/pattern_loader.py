# py_scanner/pattern_loader.py
import json
import re
import os

def load_chromium_patterns(filepath: str) -> list:
    """
    Loads the Chromium JSON, extracts 'en' regexes, and compiles them.
    Returns a list of dicts: [{'type': 'EMAIL', 'regex': compiled_regex}, ...]
    """
    if not os.path.exists(filepath):
        print(f"[WARN] Pattern file not found: {filepath}")
        return []

    compiled_patterns = []
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        for field_type, languages in data.items():
            # Skip comments or metadata keys
            if field_type.startswith("__"):
                continue
            
            # We only care about English for now
            if 'en' in languages:
                for entry in languages['en']:
                    pattern_str = entry.get('positive_pattern')
                    if pattern_str:
                        try:
                            # Compile with IGNORECASE to be lenient
                            regex = re.compile(pattern_str, re.IGNORECASE)
                            compiled_patterns.append({
                                'type': field_type,
                                'regex': regex
                            })
                        except re.error as e:
                            print(f"[WARN] Invalid Regex in {field_type}: {e}")
                            
    except Exception as e:
        print(f"[ERROR] Failed to load patterns: {e}")

    print(f"[INFO] Loaded {len(compiled_patterns)} Chromium autofill patterns.")
    return compiled_patterns