# py_scanner/llm_analyzer.py

import os
import json
import jsbeautifier
import google.generativeai as genai
from google.api_core import exceptions

# Get API Key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

def beautify_js(js_code: str) -> str:
    """
    De-minifies JavaScript to make it readable for the LLM.
    """
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        return jsbeautifier.beautify(js_code, opts)
    except Exception:
        return js_code # Fallback to raw if beautify fails

def analyze_with_llm(js_code: str, file_name: str) -> list:
    """
    Sends JS code to Google Gemini 2.5 Flash to find PII/Secrets.
    """
    if not GOOGLE_API_KEY:
        print("[WARN] No GOOGLE_API_KEY found. Skipping AI analysis.")
        return []

    # Configure the API
    genai.configure(api_key=GOOGLE_API_KEY)

    # Gemini 2.5 Flash is perfect for high-volume scanning (fast, cheap, huge context)
    # We force it to return JSON via response_mime_type
    model = genai.GenerativeModel(
        'gemini-2.5-flash',
        generation_config={"response_mime_type": "application/json"}
    )

    # 1. Optimization: Beautify the code so the LLM understands variable scope
    clean_code = beautify_js(js_code)

    # 2. Optimization: Truncate if necessary. 
    # Gemini 1.5 has a 1M token context (huge!), so we can send much more than GPT.
    # We'll cap it at ~30,000 chars to keep latency low, but you could go higher.
    if len(clean_code) > 30000:
        clean_code = clean_code[:30000] + "\n...[Code Truncated]..."

    # 3. The Prompt
    prompt = f"""
    You are a cybersecurity expert performing Static Application Security Testing (SAST).
    Your goal is to identify PII (Personally Identifiable Information) and Hardcoded Secrets.

    Analyze the following JavaScript file: "{file_name}"

    Rules:
    1. LOOK FOR: Emails, Phone Numbers, API Keys, Auth Tokens, Private Keys (RSA/DSA), Internal IP addresses.
    2. IGNORE: Code variables (e.g. "var id"), library calls, standard headers, or example/placeholder text.
    3. IGNORE: Minified variable names (a, b, c) unless they clearly contain a secret string.
    4. CRITICAL: Distinguish between REFERENCES and VALUES. 
       - If you see a filename like "config.json" or "private.key" in a list, IGNORE IT. 
       - ONLY report it if you see the ACTUAL CONTENT of the key (e.g. "MIIEpAIBA...").
    5. ONLY report findings with HIGH confidence.

    Return a JSON object with this exact schema:
    {{
        "findings": [
            {{
                "type": "Description of secret (e.g. AWS Key, Email)",
                "value": "The specific value found (snippet)",
                "confidence": "High",
                "reasoning": "Why you flagged this"
            }}
        ]
    }}
    
    If no vulnerabilities are found, return {{ "findings": [] }}

    Code to Analyze:
    ```javascript
    {clean_code}
    ```
    """

    try:
        response = model.generate_content(prompt)
        
        # Parse the JSON response
        result = json.loads(response.text)
        return result.get("findings", [])

    except exceptions.ResourceExhausted:
        print(f"[WARN] Gemini Quota Exceeded. Skipping {file_name}.")
        return []
    except json.JSONDecodeError:
        print(f"[ERROR] Gemini returned invalid JSON for {file_name}.")
        return []
    except Exception as e:
        print(f"[ERROR] Gemini Analysis failed: {e}")
        return []