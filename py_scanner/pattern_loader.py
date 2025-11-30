# py_scanner/pattern_loader.py
import json
import re
import os

def load_chromium_patterns(filepath: str) -> list:
    """
    Loads Chromium autofill patterns from a JSON file, specifically extracting
    English (en) regular expressions and compiling them.
    We're leveraging the extensive work done by the Chrome team to identify
    common PII (Personally Identifiable Information) fields.

    Args:
        filepath (str): The path to the Chromium patterns JSON file.

    Returns:
        list: A list of dictionaries, where each dictionary contains:
              - 'field_type': The category of the PII (e.g., 'EMAIL', 'PHONE').
              - 'regex': A compiled regular expression object for that type.
              Returns an empty list if the file is not found or an error occurs.
    """
    # First, let's make sure the pattern file actually exists.
    # If it doesn't, we can't load anything, so we'll just log a warning and return an empty list.
    if not os.path.exists(filepath):
        print(f"[WARN] Pattern file not found at the specified path: {filepath}")
        return []

    # This list will hold all the compiled regular expressions we successfully extract.
    compiled_patterns = []

    try:
        # We open the JSON file for reading. Using 'utf-8' encoding is a good practice
        # to handle various characters correctly.
        with open(filepath, 'r', encoding='utf-8') as file_handle:
            # Load the entire JSON content into a Python dictionary.
            data = json.load(file_handle)

        # Now, we iterate through the top-level items in the JSON data.
        # Each item represents a type of PII (like 'EMAIL' or 'PHONE') and its language-specific patterns.
        for field_type, languages_data in data.items():
            # The Chromium JSON might contain internal metadata keys that start with "__".
            # We want to ignore these as they don't contain actual patterns.
            if field_type.startswith("__"):
                continue # Skip to the next item in the loop.

            # For this project, we are currently only interested in English (en) patterns.
            # While supporting other languages would be great, we'll keep it focused for now.
            if 'en' in languages_data:
                # Get the list of English pattern entries for the current field type.
                english_entries = languages_data['en']

                # Iterate through each individual pattern entry within the English section.
                for entry in english_entries:
                    if not isinstance(entry, dict):
                        continue
                        
                    # Each entry should have a 'positive_pattern' key containing the regex string.
                    pattern_string = entry.get('positive_pattern')

                    # If a pattern string exists (it's not None or empty), we'll try to compile it.
                    if pattern_string:
                        try:
                            # Compile the regular expression. We use re.IGNORECASE because
                            # users might type in various casing, and we want to be lenient.
                            compiled_regex = re.compile(pattern_string, re.IGNORECASE)

                            # If compilation is successful, we add it to our list of patterns.
                            # We store both the original field type and the compiled regex object.
                            compiled_patterns.append({
                                'field_type': field_type,
                                'regex': compiled_regex
                            })
                        except re.error as regex_error:
                            # If a regex string is malformed, re.compile will raise an error.
                            # We'll log a warning so we know which pattern failed, but continue processing others.
                            print(f"[WARN] Invalid regular expression found for '{field_type}': {regex_error}")
            else:
                # If a field type doesn't have 'en' patterns, we simply skip it.
                # No need to log a warning here, as it's expected for some types.
                pass

    except json.JSONDecodeError as json_error:
        # This specific error occurs if the file is not valid JSON.
        print(f"[ERROR] Failed to parse JSON from '{filepath}': {json_error}")
    except IOError as io_error:
        # This handles errors like permission denied or other file system issues.
        print(f"[ERROR] Could not read file '{filepath}': {io_error}")
    except Exception as general_error:
        # Catch any other unexpected errors during the loading process.
        print(f"[ERROR] An unexpected error occurred while loading patterns: {general_error}")

    # After attempting to load all patterns, we'll print a summary of what was loaded.
    print(f"[INFO] Successfully loaded {len(compiled_patterns)} Chromium autofill patterns from {filepath}.")
    return compiled_patterns