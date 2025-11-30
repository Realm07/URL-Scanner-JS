import asyncio
import sys
import os
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import shutil

# Add project root to path
sys.path.append(str(Path(__file__).parent.parent))

from py_scanner.crawler import crawl_and_collect

PORT = 8000
BASE_URL = f"http://localhost:{PORT}/index.html"
ASSETS_DIR = Path(__file__).parent / "assets"
OUTPUT_DIR = Path(__file__).parent / "output"

def start_server():
    os.chdir(ASSETS_DIR)
    httpd = HTTPServer(('localhost', PORT), SimpleHTTPRequestHandler)
    httpd.serve_forever()

async def run_test():
    # Start server in a thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give server a moment to start
    await asyncio.sleep(1)
    
    print("--- Testing Mode: js-only (Default) ---")
    if OUTPUT_DIR.exists(): shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir()
    
    results = await crawl_and_collect(BASE_URL, 1, OUTPUT_DIR, scan_mode='js-only')
    print(f"Collected: {list(results.keys())}")
    
    # Expect: script.js ONLY. No inline, no comp.jsx
    assert any(k.endswith('script.js') for k in results.keys()), "script.js should be found"
    assert not any(k.endswith('comp.jsx') for k in results.keys()), "comp.jsx should NOT be found in js-only mode"
    assert not any('inline-script' in k for k in results.keys()), "inline scripts should NOT be found in js-only mode"
    print("PASS: js-only mode")

    print("\n--- Testing Mode: external ---")
    if OUTPUT_DIR.exists(): shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir()
    
    results = await crawl_and_collect(BASE_URL, 1, OUTPUT_DIR, scan_mode='external')
    print(f"Collected: {list(results.keys())}")
    
    # Expect: script.js AND comp.jsx. No inline.
    assert any(k.endswith('script.js') for k in results.keys()), "script.js should be found"
    assert any(k.endswith('comp.jsx') for k in results.keys()), "comp.jsx should be found in external mode"
    assert not any('inline-script' in k for k in results.keys()), "inline scripts should NOT be found in external mode"
    print("PASS: external mode")

    print("\n--- Testing Mode: all ---")
    if OUTPUT_DIR.exists(): shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir()
    
    results = await crawl_and_collect(BASE_URL, 1, OUTPUT_DIR, scan_mode='all')
    print(f"Collected: {list(results.keys())}")
    
    # Expect: script.js, comp.jsx, AND inline.
    assert any(k.endswith('script.js') for k in results.keys()), "script.js should be found"
    assert any(k.endswith('comp.jsx') for k in results.keys()), "comp.jsx should be found in all mode"
    assert any('inline-script' in k for k in results.keys()), "inline scripts should be found in all mode"
    print("PASS: all mode")

if __name__ == "__main__":
    asyncio.run(run_test())
