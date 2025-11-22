import re
import asyncio
from pathlib import Path
from collections import deque
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright, Error

from py_scanner.utils import sanitize_filename

IGNORED_EXTENSIONS = [
    '.zip', '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.css', '.ico',
    '.woff', '.woff2', '.ttf', '.eot', '.svg', '.mp4', '.mp3'
]

async def crawl_and_collect(start_url: str, max_pages: int, js_output_dir: Path) -> dict[str, str]:
    """
    Crawls a website and collects both external AND inline JavaScript.
    Also attempts to discover dynamically imported files (chunks/config).
    """
    print(f"[INFO] Starting crawl from: {start_url}")
    
    try:
        start_domain = urlparse(start_url).hostname
        if not start_domain:
            print(f"[ERROR] Invalid start URL: Could not parse hostname from {start_url}")
            return {}
    except ValueError as e:
        print(f"[ERROR] Invalid start URL: {e}")
        return {}

    urls_to_visit = deque([start_url])
    visited_urls = set()
    collected_scripts = {}
    import_pattern = re.compile(r'(?:import\s+(?:.*?from\s+)?["\']([^"\']+)["\'])|(?:import\(["\']([^"\']+)["\']\))')
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()

        async def handle_response(response):
            content_type = response.headers.get('content-type', '')
            # Capture standard JS files AND files ending in common JS extensions
            if 'javascript' in content_type or response.url.endswith(('.js', '.jsx', '.ts', '.tsx')):
                if response.url not in collected_scripts:
                    try:
                        content = await response.text()
                        collected_scripts[response.url] = content
                        
                        # --- IMPROVED IMPORT DISCOVERY ---
                        matches = import_pattern.findall(content)
                        for match in matches:
                            # match is a tuple, pick the non-empty one
                            relative_path = match[0] or match[1]
                            
                            # FILTER: Skip node_modules, external links, and suspicious dynamic strings
                            if (relative_path.startswith('http') or 
                                'node_modules' in relative_path or 
                                '{' in relative_path or 
                                ' ' in relative_path):
                                continue
                            
                            # Clean up path (remove query params if any)
                            relative_path = relative_path.split('?')[0]

                            # Candidate generation (handling missing extensions)
                            candidates = [relative_path]
                            if not any(relative_path.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx']):
                                candidates = [
                                    f"{relative_path}.js",
                                    f"{relative_path}.jsx",
                                    f"{relative_path}.ts",
                                    f"{relative_path}.tsx"
                                ]
                            
                            for candidate in candidates:
                                try:
                                    # Handle absolute imports like "/src/config.js"
                                    if candidate.startswith('/'):
                                        # Join with the root domain, not the current file's URL
                                        parsed_start = urlparse(start_url)
                                        base = f"{parsed_start.scheme}://{parsed_start.netloc}"
                                        new_script_url = urljoin(base, candidate)
                                    else:
                                        # Relative import
                                        new_script_url = urljoin(response.url, candidate)
                                    
                                    parsed_new = urlparse(new_script_url)
                                    if (parsed_new.hostname == start_domain and 
                                        new_script_url not in visited_urls and 
                                        new_script_url not in urls_to_visit):
                                        urls_to_visit.appendleft(new_script_url)
                                except:
                                    pass
                        
                        # Save the file locally
                        filename = sanitize_filename(response.url) + ".js"
                        filepath = js_output_dir / filename
                        with open(filepath, 'w', encoding='utf-8') as f:
                            f.write(content)
                    except Exception:
                        pass
        
        page.on('response', handle_response)
        
        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.popleft()
            if current_url in visited_urls:
                continue

            print(f"[CRAWLING] ({len(visited_urls) + 1}/{max_pages}) Visiting: {current_url}")
            visited_urls.add(current_url)

            try:
                await page.goto(current_url, wait_until='networkidle', timeout=30000)
                
                # --- INLINE SCRIPT COLLECTION ---
                inline_scripts = await page.eval_on_selector_all(
                    'script:not([src])', 
                    'scripts => scripts.map(s => s.textContent)'
                )
                
                for i, script_content in enumerate(inline_scripts):
                    if script_content:
                        inline_script_url = f"{current_url}#inline-script-{i+1}"
                        if inline_script_url not in collected_scripts:
                            collected_scripts[inline_script_url] = script_content
                            filename = sanitize_filename(inline_script_url) + ".js"
                            filepath = js_output_dir / filename
                            with open(filepath, 'w', encoding='utf-8') as f:
                                f.write(script_content)

                # --- LINK DISCOVERY ---
                links = await page.eval_on_selector_all('a', 'as => as.map(a => a.href)')
                
                for link in links:
                    try:
                        absolute_link = urljoin(current_url, link).split('#')[0]
                        if any(absolute_link.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
                            continue
                        parsed_link = urlparse(absolute_link)
                        if (parsed_link.hostname == start_domain and 
                            absolute_link not in visited_urls and 
                            absolute_link not in urls_to_visit):
                            urls_to_visit.append(absolute_link)
                    except Exception:
                        continue
            except Error as e:
                # It's common for some pages to fail or timeout, just log and continue
                print(f"[DEBUG] Playwright error on page {current_url}: {e}")
            except Exception as e:
                print(f"[ERROR] Could not process page {current_url}: {e}")
        
        await browser.close()
    
    print(f"\n[INFO] Crawl complete. Visited {len(visited_urls)} pages.")
    print(f"[INFO] Found and saved {len(collected_scripts)} unique scripts (external and inline).")
    return collected_scripts