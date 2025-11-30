# tests/verify_scan_modes.py

import asyncio
import sys
import os
from pathlib import Path
from http.server import HTTPServer, SimpleHTTPRequestHandler
import threading
import shutil

# we need to tell python where to find our code, since we're running from the tests folder.
# this adds the project root to the python path.
sys.path.append(str(Path(__file__).parent.parent))

from py_scanner.crawler import crawl_and_collect

# configuration for our little test server.
PORT = 8000
BASE_URL = f"http://localhost:{PORT}/index.html"
ASSETS_DIR = Path(__file__).parent / "assets"
OUTPUT_DIR = Path(__file__).parent / "output"

def start_server():
    """
    starts a simple http server to serve our test assets.
    we need this because the crawler expects a real web server, not just files on disk.
    """
    os.chdir(ASSETS_DIR)
    # we suppress the logs because they clutter up the test output.
    # if you're debugging the server, you might want to remove this.
    class QuietHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
            
    httpd = HTTPServer(('localhost', PORT), QuietHandler)
    httpd.serve_forever()

async def run_test():
    """
    this is the main test runner.
    it checks if our 'scan_mode' feature is actually working.
    we have 3 modes:
    1. js-only: only .js files (strict)
    2. external: .js, .jsx, .ts, etc (loose)
    3. all: everything above + inline scripts in the html
    """
    
    # spin up the server in a background thread so it doesn't block the test.
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # give the server a second to wake up.
    await asyncio.sleep(1)
    
    print("--- Testing Mode: js-only (Default) ---")
    # clean up previous runs so we don't get false positives.
    if OUTPUT_DIR.exists(): shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir()
    
    # run the crawler!
    results = await crawl_and_collect(BASE_URL, 1, OUTPUT_DIR, scan_mode='js-only')
    print(f"Collected: {list(results.keys())}")
    
    # in strict mode, we should ONLY see the .js file.
    # comp.jsx and the inline script should be ignored.
    assert any(k.endswith('script.js') for k in results.keys()), "script.js should be found"
    assert not any(k.endswith('comp.jsx') for k in results.keys()), "comp.jsx should NOT be found in js-only mode"
    assert not any('inline-script' in k for k in results.keys()), "inline scripts should NOT be found in js-only mode"
    print("PASS: js-only mode")

    print("\n--- Testing Mode: external ---")
    if OUTPUT_DIR.exists(): shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir()
    
    results = await crawl_and_collect(BASE_URL, 1, OUTPUT_DIR, scan_mode='external')
    print(f"Collected: {list(results.keys())}")
    
    # in external mode, we allow other extensions like .jsx.
    # but we still ignore inline scripts.
    assert any(k.endswith('script.js') for k in results.keys()), "script.js should be found"
    assert any(k.endswith('comp.jsx') for k in results.keys()), "comp.jsx should be found in external mode"
    assert not any('inline-script' in k for k in results.keys()), "inline scripts should NOT be found in external mode"
    print("PASS: external mode")

    print("\n--- Testing Mode: all ---")
    if OUTPUT_DIR.exists(): shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir()
    
    results = await crawl_and_collect(BASE_URL, 1, OUTPUT_DIR, scan_mode='all')
    print(f"Collected: {list(results.keys())}")
    
    # in 'all' mode, we want EVERYTHING.
    assert any(k.endswith('script.js') for k in results.keys()), "script.js should be found"
    assert any(k.endswith('comp.jsx') for k in results.keys()), "comp.jsx should be found in all mode"
    assert any('inline-script' in k for k in results.keys()), "inline scripts should be found in all mode"
    print("PASS: all mode")

if __name__ == "__main__":
    asyncio.run(run_test())
