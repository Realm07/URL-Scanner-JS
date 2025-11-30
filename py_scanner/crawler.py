import re
import asyncio
from pathlib import Path
from collections import deque
from urllib.parse import urlparse, urljoin
from playwright.async_api import async_playwright, Error

from py_scanner.utils import sanitize_filename

# we're skipping these because they aren't code.
# scanning a pdf or a font file for javascript vulnerabilities is a waste of time.
IGNORED_EXTENSIONS = [
    '.zip', 
    '.pdf', 
    '.png', 
    '.jpg', 
    '.jpeg', 
    '.gif', 
    '.css', 
    '.ico',
    '.woff', 
    '.woff2', 
    '.ttf', 
    '.eot', 
    '.svg', 
    '.mp4', 
    '.mp3'
]

async def crawl_and_collect(start_url: str, max_pages: int, js_output_dir: Path, scan_mode: str = 'js-only') -> dict[str, str]:
    """
    this is our main spider. it crawls the website and grabs every piece of javascript it can find.
    we use a real browser (playwright) because modern sites are complex and often load scripts dynamically.
    """
    print(f"[INFO] Starting crawl from: {start_url} (Mode: {scan_mode})")
    
    # basic sanity check. if we can't parse the domain, we can't enforce scope.
    try:
        start_domain = urlparse(start_url).hostname
        if not start_domain:
            print(f"[ERROR] Invalid start URL: Could not parse hostname from {start_url}")
            return {}
    except ValueError as e:
        print(f"[ERROR] Invalid start URL: {e}")
        return {}

    # we use a queue for the pages we need to visit, and a set for the ones we've already seen.
    # this prevents us from going in circles.
    urls_to_visit = deque([start_url])
    visited_urls = set()
    
    # this is where we store the code we find.
    # key = url of the script, value = the actual code.
    collected_scripts = {}
    
    # regex to find imports.
    # we're looking for things like: import ... from "file.js" OR import("file.js")
    # this helps us find files that the browser might not have loaded yet (lazy loading).
    import_pattern = re.compile(r'(?:import\s+(?:.*?from\s+)?["\']([^"\']+)["\'])|(?:import\(["\']([^"\']+)["\']\))')
    
    async with async_playwright() as playwright:
        # we launch chromium because it's the most common engine.
        browser = await playwright.chromium.launch()
        page = await browser.new_page()

        # this function is our "man in the middle".
        # instead of scraping the html for <script> tags, we listen to the network traffic.
        # this is way better because it catches scripts loaded by other scripts, or injected by ad networks.
        async def handle_response(response):
            # first, we check if we even care about this file.
            content_type = response.headers.get('content-type', '')
            url = response.url
            
            is_interesting = False
            
            # if we're in 'js-only' mode, we're strict. it has to end in .js.
            if scan_mode == 'js-only':
                if url.split('?')[0].endswith('.js'):
                    is_interesting = True
            # otherwise, we're a bit more loose. we'll take anything that looks like javascript.
            else:
                if 'javascript' in content_type or url.split('?')[0].endswith(('.js', '.jsx', '.ts', '.tsx')):
                    is_interesting = True

            if is_interesting and url not in collected_scripts:
                try:
                    # grab the code!
                    content = await response.text()
                    collected_scripts[url] = content
                    
                    # now we play detective. we read the code we just found to see if it imports OTHER files.
                    # this is how we find those hidden chunks that only load when you click a specific button.
                    matches = import_pattern.findall(content)
                    for match in matches:
                        # regex returns a tuple, we just want the part that matched.
                        relative_path = match[0] or match[1]
                        
                        # filter out junk.
                        if (relative_path.startswith('http') or 
                            'node_modules' in relative_path or 
                            '{' in relative_path or 
                            ' ' in relative_path):
                            continue
                        
                        # clean up the path.
                        relative_path = relative_path.split('?')[0]

                        # sometimes imports don't have extensions (e.g. import './utils').
                        # we have to guess.
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
                                # resolve the relative path to a full url.
                                if candidate.startswith('/'):
                                    parsed_start = urlparse(start_url)
                                    base = f"{parsed_start.scheme}://{parsed_start.netloc}"
                                    new_script_url = urljoin(base, candidate)
                                else:
                                    new_script_url = urljoin(url, candidate)
                                
                                parsed_new = urlparse(new_script_url)
                                
                                # critical check: stay on the target domain!
                                # we do NOT want to start scanning google analytics or facebook pixel code.
                                if (parsed_new.hostname == start_domain and 
                                    new_script_url not in visited_urls and 
                                    new_script_url not in urls_to_visit):
                                    urls_to_visit.appendleft(new_script_url)
                            except:
                                pass
                    
                    # save the file to disk so we can look at it later if we need to debug.
                    filename = sanitize_filename(url) + ".js"
                    filepath = js_output_dir / filename
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(content)
                except Exception:
                    # sometimes responses fail (404, 500, etc). we just ignore them.
                    pass
        
        # hook up our listener.
        page.on('response', handle_response)
        
        # main crawling loop.
        while urls_to_visit and len(visited_urls) < max_pages:
            current_url = urls_to_visit.popleft()
            if current_url in visited_urls:
                continue

            print(f"[CRAWLING] ({len(visited_urls) + 1}/{max_pages}) Visiting: {current_url}")
            visited_urls.add(current_url)

            try:
                # we wait for 'networkidle' which means "no network connections for at least 500ms".
                # this gives the page time to finish loading all its scripts.
                await page.goto(current_url, wait_until='networkidle', timeout=30000)
                
                # if the user wants 'all' scripts, we also grab inline scripts (code inside <script> tags without a src).
                if scan_mode == 'all':
                    inline_scripts = await page.eval_on_selector_all(
                        'script:not([src])', 
                        'scripts => scripts.map(s => s.textContent)'
                    )
                    
                    for i, script_content in enumerate(inline_scripts):
                        if script_content:
                            # we make up a fake url for these so they fit our system.
                            inline_script_url = f"{current_url}#inline-script-{i+1}"
                            if inline_script_url not in collected_scripts:
                                collected_scripts[inline_script_url] = script_content
                                filename = sanitize_filename(inline_script_url) + ".js"
                                filepath = js_output_dir / filename
                                with open(filepath, 'w', encoding='utf-8') as f:
                                    f.write(script_content)

                # find links to other pages on the same site so we can keep crawling.
                links = await page.eval_on_selector_all('a', 'as => as.map(a => a.href)')
                
                for link in links:
                    try:
                        absolute_link = urljoin(current_url, link).split('#')[0]
                        
                        # skip boring files.
                        if any(absolute_link.lower().endswith(ext) for ext in IGNORED_EXTENSIONS):
                            continue
                            
                        parsed_link = urlparse(absolute_link)
                        
                        # stay on target!
                        if (parsed_link.hostname == start_domain and 
                            absolute_link not in visited_urls and 
                            absolute_link not in urls_to_visit):
                            urls_to_visit.append(absolute_link)
                    except Exception:
                        continue
            except Error as e:
                # playwright errors happen. timeouts, crashes, etc. just log it and move on.
                print(f"[DEBUG] Playwright error on page {current_url}: {e}")
            except Exception as e:
                print(f"[ERROR] Could not process page {current_url}: {e}")
        
        await browser.close()
    
    print(f"\n[INFO] Crawl complete. Visited {len(visited_urls)} pages.")
    print(f"[INFO] Found and saved {len(collected_scripts)} unique scripts.")
    return collected_scripts