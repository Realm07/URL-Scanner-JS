import asyncio
import argparse
import yaml
from pathlib import Path
from urllib.parse import urlparse
import jsbeautifier

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
    "chunk-", "npm", "assets/" # Generic asset folders often contain 3rd party blobs
]

async def analyze_file_task(script_url, script_code, config, semaphore, all_findings):
    # 1. Filter (Same)
    if any(k in script_url.lower() for k in IGNORE_KEYWORDS):
        return

    print(f"[ANALYZING] {script_url}...")
    
    file_has_vulnerability = False 
    heuristic_hits = 0
    
    # --- 2. Hybrid Scan Strategy ---
    parsed_data = parse_js_to_ast(script_code)
    
    if parsed_data:
        # Strategy A: High-Precision AST Scan
        findings = list(scan_ast_and_comments(parsed_data, config))
        for finding in findings:
            finding['file_url'] = script_url
            finding['method'] = "Heuristic (AST)"
            all_findings.append(finding)
            heuristic_hits += 1
            file_has_vulnerability = True
    else:
        # Strategy B: Fallback Raw Text Scan
        # If AST failed, we MUST check the text manually.
        print(f"  [!] AST failed for {script_url}. Running Raw Text fallback.")
        findings = list(scan_raw_text(script_code, config))
        for finding in findings:
            finding['file_url'] = script_url
            finding['method'] = "Heuristic (Raw)"
            all_findings.append(finding)
            heuristic_hits += 1
            file_has_vulnerability = True

    # --- 3. Smart Decision: LLM Trigger ---
    should_llm_scan = False
    
    # Condition A: Heuristic Hit (AST or Raw)
    if heuristic_hits > 0:
        should_llm_scan = True
    
    # Condition B: Critical Filenames (Expanded List)
    # Added 'app', 'index', 'router', 'routes' to catch App.jsx and routing files
    critical_terms = [
        "config", "env", "secret", "settings", "key", "token", 
        "auth", "login", "register", "user", "account", "profile",
        "admin", "dashboard", "utils", "api", "service",
        "app.", "index.", "router", "routes" 
    ]
    
    if any(term in script_url.lower() for term in critical_terms):
        should_llm_scan = True
        # Debug print to see why it triggered
        # print(f"  >> Triggered by filename: {script_url}")

    # --- 4. LLM Execution (Same) ---
    if should_llm_scan:
        print(f"  >> [AI] Queuing LLM scan for {script_url}...")
        async with semaphore:
            llm_results = await asyncio.to_thread(analyze_with_llm, script_code, script_url)
            
            if llm_results:
                file_has_vulnerability = True # HIT!
                print(f"  $$ [AI] HIT! Gemini found {len(llm_results)} issues in {script_url}")
                for l_res in llm_results:
                    all_findings.append({
                        "type": f"LLM Detected: {l_res.get('type')}",
                        "details": f"Value: {l_res.get('value')} (Confidence: {l_res.get('confidence')})",
                        "file_url": script_url,
                        "line": 0, 
                        "method": "AI (LLM)"
                    })

    # --- NEW: AUTO-BEAUTIFY FEATURE ---
    if file_has_vulnerability:
        try:
            # Create a readable filename
            from py_scanner.utils import sanitize_filename # Ensure this is imported or available
            
            safe_name = sanitize_filename(script_url)
            # We need the output path (passed or calculated). 
            # For simplicity here, we'll assume a fixed relative path or you can pass output_dir to this function.
            # A robust way is to recalculate the path similar to main():
            domain = urlparse(script_url).hostname
            if domain:
                save_path = Path("output") / domain / "js_files" / f"{safe_name}.readable.js"
                
                # Make it readable
                beautified_code = jsbeautifier.beautify(script_code)
                
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(beautified_code)
                    
                print(f"  [+] Saved readable copy to: {save_path}")
        except Exception as e:
            print(f"  [!] Failed to save readable copy: {e}")

async def main():
    parser = argparse.ArgumentParser(description="AST-based client-side vulnerability scanner.")
    parser.add_argument("-u", "--url", required=True, help="The starting URL to scan.")
    parser.add_argument("-m", "--max-pages", type=int, default=10, help="Maximum number of pages to crawl.")
    args = parser.parse_args()

    # 1. Load Configuration
    try:
        with open("config.yaml", 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except Exception as e:
        print(f"[ERROR] Config error: {e}")
        return

    initialize_chromium_rules("chromium_patterns.json")

    # 2. Setup Output
    try:
        domain = urlparse(args.url).hostname
        if not domain: raise ValueError
        output_dir = Path("output") / domain
        js_dir = output_dir / "js_files"
        js_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        print("[ERROR] Invalid URL.")
        return

    # 3. Crawl
    js_scripts = await crawl_and_collect(args.url, args.max_pages, js_dir)

    if not js_scripts:
        print("[INFO] No JS files found.")
        return

    # 4. Parallel Analysis
    print(f"\n[INFO] Starting Parallel Analysis on {len(js_scripts)} files...")
    
    all_findings = []
    
    # Rate Limiter: Only allow 3 LLM calls at the same time to avoid 429 errors
    # Free tier Gemini/OpenAI has limits. 3 is safe.
    llm_semaphore = asyncio.Semaphore(3)
    
    tasks = []
    for url, code in js_scripts.items():
        task = analyze_file_task(url, code, config, llm_semaphore, all_findings)
        tasks.append(task)
    
    # Run all file analysis tasks concurrently
    await asyncio.gather(*tasks)

    # 5. Reporting
    print("-" * 40)
    if all_findings:
        print(f"[SUCCESS] Found {len(all_findings)} potential vulnerabilities.")
        
        save_findings_to_csv(all_findings, output_dir / "ast_scan_results.csv")
        generate_html_report(all_findings, domain, output_dir / "ast_scan_report.html")
        
        # Print simplified summary
        for finding in all_findings:
            print(f"[!] {finding['type']} in {finding['file_url']}")
    else:
        print("[INFO] No vulnerabilities found.")
    print("-" * 40)

if __name__ == "__main__":
    asyncio.run(main())