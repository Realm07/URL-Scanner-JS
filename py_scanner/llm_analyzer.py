# py_scanner/llm_analyzer.py

import os
import json
import jsbeautifier
import google.generativeai as genai
from google.api_core import exceptions

# get api key
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

def beautify_js(js_code: str) -> str:
    """
    llms are smart, but they struggle with minified spaghetti code just like we do.
    unrolling the code helps the model understand variable scope and context.
    """
    try:
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        return jsbeautifier.beautify(js_code, opts)
    except Exception:
        return js_code # fallback to raw if beautify fails

def analyze_with_llm(js_code: str, file_name: str) -> list:
    """
    sends the code to google gemini to find things that regex misses.
    regex is great for "AWS_KEY=...", but terrible for "the password is the user's birthday".
    """
    if not GOOGLE_API_KEY:
        print("[WARN] No GOOGLE_API_KEY found. Skipping AI analysis.")
        return []

    # configure the api
    genai.configure(api_key=GOOGLE_API_KEY)
    
    # we're using gemini 2.5 flash here.
    # why? because it's fast, cheap, and has a massive context window.
    # we don't need gpt-4 level reasoning to spot a hardcoded password.
    model = genai.GenerativeModel(
        'gemini-2.5-flash-lite',
        generation_config={
            "response_mime_type": "application/json"
        }
    )

    # 1. optimization: beautify the code so the llm understands variable scope
    clean_code = beautify_js(js_code)

    # 2. optimization: truncate if necessary. 
    # gemini has a huge context window, but we still want to be polite to the api
    # and keep our latency down. 30k chars is usually enough to capture the config block.
    if len(clean_code) > 30000:
        clean_code = clean_code[:30000] + "\n...[Code Truncated]..."

    # 3. the prompt
    # this is the most important part. we have to be very specific about what we want,
    # otherwise the model will hallucinate vulnerabilities or flag harmless things.
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
    5. ONLY report findings with HIGH and MEDIUM confidence.

    Return a JSON object with this exact schema:
    {{
        "findings": [
            {{
                "type": "Description of secret (e.g. AWS Key, Email)",
                "value": "The specific value found (snippet)",
                "confidence": "High/Medium",
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
        
        # parse the json response
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