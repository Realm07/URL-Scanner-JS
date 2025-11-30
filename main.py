# main.py

import asyncio
import argparse
import yaml
import sys
import os
from pathlib import Path
from urllib.parse import urlparse
from datetime import datetime

# keeping our imports clean. these are the core modules that power the scanner.
from py_scanner.crawler import crawl_and_collect
from py_scanner.js_parser import parse_js_to_ast
from py_scanner.ast_scanner import scan_ast_and_comments, initialize_chromium_rules, scan_raw_text
from py_scanner.utils import save_findings_to_csv
from py_scanner.reporter import generate_html_report
from py_scanner.llm_analyzer import analyze_with_llm

IGNORE_KEYWORDS = [
    "vendor", "jquery", "bootstrap", "polyfill", "runtime", 
    "node_modules", "framework", "bundle", "min.js", 
    "cookieconsent", "high-contrast", "zone.js",
    "react", "angular", "vue", "backbone", "lodash", "underscore",
    "chart", "d3", "three", "moment", "axios",
    "chunk-", "npm", "assets/"
]

# we need a global way to send logs back to the ui without passing
# the callback through every single function call.
LOG_CALLBACK = None

def log(message):
    """
    simple wrapper to handle dual logging:
    1. to the terminal (so we can see what's happening locally)
    2. to the web ui (via the callback, if it's set)
    """
    print(message) 
    if LOG_CALLBACK:
        LOG_CALLBACK(message) 

async def analyze_file_task(script_url, script_code, config, semaphore, all_findings):
    if any(k in script_url.lower() for k in IGNORE_KEYWORDS):
        return

    log(f"[ANALYZING] {script_url}...")
    
    file_has_vulnerability = False 
    heuristic_hits = 0
    
    parsed_data = parse_js_to_ast(script_code)
    
    if parsed_data:
        findings = list(scan_ast_and_comments(parsed_data, config))
        for finding in findings:
            finding['file_url'] = script_url
            finding['method'] = "Heuristic (AST)"
            all_findings.append(finding)
            heuristic_hits += 1
            file_has_vulnerability = True
    else:
        # fallback time. if esprima chokes on the js (which happens a lot with modern syntax),
        # we switch to a "dumb" regex scan. it's less accurate but better than nothing.
        log(f"  [!] AST failed for {script_url}. Running Raw Text fallback.")
        findings = list(scan_raw_text(script_code, config))
        for finding in findings:
            finding['file_url'] = script_url
            finding['method'] = "Heuristic (Raw)"
            all_findings.append(finding)
            heuristic_hits += 1
            file_has_vulnerability = True

    should_llm_scan = False
    
    if heuristic_hits > 0:
        should_llm_scan = True
    
    # we want to be smart about when we call the llm because it's expensive and slow.
    # if the file name looks interesting (e.g. "auth.js" or "config.js"), we force a scan
    # even if the heuristics didn't find anything.
    critical_terms = [
        "config", "env", "secret", "settings", "key", "token", 
        "auth", "login", "register", "user", "account", "profile",
        "admin", "dashboard", "utils", "api", "service",
        "app.", "index.", "router", "routes" 
    ]
    
    if any(term in script_url.lower() for term in critical_terms):
        should_llm_scan = True

    if should_llm_scan:
        log(f"  >> [AI] Queuing LLM scan for {script_url}...")
        async with semaphore:
            # we're offloading the heavy lifting to a thread here to avoid blocking the event loop.
            llm_results = await asyncio.to_thread(analyze_with_llm, script_code, script_url)
            
            if llm_results:
                file_has_vulnerability = True
                log(f"  $$ [AI] HIT! Gemini found {len(llm_results)} issues in {script_url}")
                for l_res in llm_results:
                    all_findings.append({
                        "type": f"LLM Detected: {l_res.get('type')}",
                        "details": f"Value: {l_res.get('value')} (Confidence: {l_res.get('confidence')})",
                        "file_url": script_url,
                        "line": 0, 
                        "method": "AI (LLM)"
                    })

    if file_has_vulnerability:
        try:
            import jsbeautifier
            from py_scanner.utils import sanitize_filename
            
            # if we found something, we want to save a readable copy of the code.
            # minified js is a nightmare to debug, so we run it through a beautifier first.
            parsed_url = urlparse(script_url)
            domain_str = f"{parsed_url.hostname}_{parsed_url.port}" if parsed_url.port else parsed_url.hostname
            safe_name = sanitize_filename(script_url)
            
            save_path = Path("output") / domain_str / "js_files" / f"{safe_name}.readable.js"
            save_path.parent.mkdir(parents=True, exist_ok=True)

            beautified_code = jsbeautifier.beautify(script_code)
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(beautified_code)
            log(f"  [+] Saved readable copy: {safe_name}.readable.js")
        except Exception as e:
            pass

async def run_scanner_core(url, max_pages, api_key=None, scan_mode='js-only'):
    """
    this is the brain of the operation. it orchestrates the whole flow:
    crawling -> parsing -> scanning -> reporting.
    """
    
    # if the user provided an api key in the ui, we override the env var.
    if api_key:
        os.environ["GOOGLE_API_KEY"] = api_key

    try:
        with open("config.yaml", 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        log(f"[ERROR] Config error: {e}")
        return

    initialize_chromium_rules("chromium_patterns.json")

    try:
        parsed = urlparse(url)
        if not parsed.hostname: raise ValueError
        
        # we separate outputs by domain + port to avoid overwriting results
        # if you scan localhost:3000 and localhost:8000 back-to-back.
        domain_folder = f"{parsed.hostname}_{parsed.port}" if parsed.port else parsed.hostname
        
        output_dir = Path("output") / domain_folder
        js_dir = output_dir / "js_files"
        js_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        log("[ERROR] Invalid URL.")
        return

    js_scripts = await crawl_and_collect(url, max_pages, js_dir, scan_mode=scan_mode)

    if not js_scripts:
        log("[INFO] No JS files found.")
        return

    log(f"\n[INFO] Starting Parallel Analysis on {len(js_scripts)} files...")
    
    all_findings = []
    # limit concurrency so we don't blow up the cpu or hit api rate limits.
    llm_semaphore = asyncio.Semaphore(3)
    
    tasks = []
    for script_url, code in js_scripts.items():
        task = analyze_file_task(script_url, code, config, llm_semaphore, all_findings)
        tasks.append(task)
    
    await asyncio.gather(*tasks)

    log("-" * 40)
    if all_findings:
        log(f"[SUCCESS] Found {len(all_findings)} potential vulnerabilities.")
        
        save_findings_to_csv(all_findings, output_dir / "ast_scan_results.csv")
        generate_html_report(all_findings, url, output_dir / "ast_scan_report.html")
        
        log(f"[REPORT] Report generated at output/{domain_folder}/ast_scan_report.html")
    else:
        log("[INFO] No vulnerabilities found.")
    log("-" * 40)

# wrapper to run async from sync context
def start_scan(url, max_pages, api_key=None, callback=None, scan_mode='js-only'):
    global LOG_CALLBACK
    LOG_CALLBACK = callback
    asyncio.run(run_scanner_core(url, max_pages, api_key, scan_mode))

# cli entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-m", "--max-pages", type=int, default=10)
    parser.add_argument("--scan-mode", choices=['all', 'external', 'js-only'], default='js-only', help="Scanning mode: 'all' (everything), 'external' (no inline), 'js-only' (.js files only)")
    args = parser.parse_args()
    start_scan(args.url, args.max_pages, scan_mode=args.scan_mode)