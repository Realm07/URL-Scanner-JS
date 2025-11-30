from flask import Flask, render_template, request, jsonify, Response, send_from_directory
import os
import queue
import threading
import yaml
from pathlib import Path
from main import start_scan

app = Flask(__name__)

# we need a thread-safe way to pass logs from the background scanner
# to the main flask thread. a simple queue is the easiest solution here.
# think of it like a conveyor belt: scanner puts logs on, flask takes them off.
log_queue = queue.Queue()

def log_to_queue(message):
    """
    this is the bridge between the scanner and the web ui.
    we pass this callback to the scanner so it can dump logs without
    knowing anything about flask or the request context.
    """
    log_queue.put(message)

@app.route('/')
def index():
    """
    renders the main dashboard. nothing fancy here.
    """
    # we're using the filesystem as our database.
    # it's a bit hacky, but for a local tool, it saves us from setting up sqlite.
    # we just look for folders in the output directory.
    history = []
    output_path = Path("output")
    if output_path.exists():
        for p in output_path.iterdir():
            if p.is_dir():
                # check if we actually generated a report for this scan.
                report_file = p / "ast_scan_report.html"
                has_report = report_file.exists()
                history.append({
                    "name": p.name,
                    "has_report": has_report,
                    "path": str(p)
                })
    
    # grab the current config so we can show it in the settings editor.
    # if the file's missing, we just show an empty box.
    config_content = ""
    if Path("config.yaml").exists():
        with open("config.yaml", 'r') as f:
            config_content = f.read()

    return render_template('index.html', history=history, config=config_content)

@app.route('/start_scan', methods=['POST'])
def run_scan():
    """
    kicks off the scanning process.
    """
    data = request.json
    url = data.get('url')
    max_pages = int(data.get('max_pages', 10))
    api_key = data.get('api_key')
    scan_mode = data.get('scan_mode', 'js-only')

    if not url:
        return jsonify({"status": "error", "message": "URL is required"}), 400

    # this is the tricky part. the scan can take minutes, so we absolutely
    # cannot run it in the main request thread or we'll block the whole server.
    # we spin up a daemon-ish thread to do the heavy lifting.
    def target():
        try:
            start_scan(url, max_pages, api_key, callback=log_to_queue, scan_mode=scan_mode)
            log_to_queue("[DONE] Scan Finished.")
        except Exception as e:
            # if something blows up in the thread, we need to make sure
            # the ui knows about it, otherwise the loading spinner spins forever.
            log_to_queue(f"[ERROR] {str(e)}")
            log_to_queue("[DONE] Scan Failed.")

    thread = threading.Thread(target=target)
    thread.start()

    return jsonify({"status": "started"})

@app.route('/stream_logs')
def stream_logs():
    """
    handles the real-time log streaming using server-sent events (sse).
    websockets were overkill for this. sse is simple and works great for one-way updates.
    """
    def generate():
        while True:
            try:
                # we block here for a second waiting for logs.
                # if nothing comes, we hit the empty exception.
                message = log_queue.get(timeout=1.0) 
                yield f"data: {message}\n\n"
                
                # this is our signal to close the stream from the client side.
                if "[DONE]" in message:
                    break
            except queue.Empty:
                # this is important! some browsers/proxies will kill the connection
                # if it's idle for too long. sending a comment keeps it alive.
                yield ": keep-alive\n\n"
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/view_report/<path:folder_name>')
def view_report(folder_name):
    """
    just serves the static html report we generated.
    """
    path = Path("output") / folder_name
    return send_from_directory(path, "ast_scan_report.html")

@app.route('/save_settings', methods=['POST'])
def save_settings():
    """
    saves the config yaml from the frontend editor.
    """
    new_config = request.json.get('config')
    try:
        # sanity check: make sure it's actually valid yaml before we save it.
        # we don't want to crash the scanner next time it runs.
        yaml.safe_load(new_config)
        with open("config.yaml", 'w') as f:
            f.write(new_config)
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

if __name__ == '__main__':
    # just in case the user deleted it.
    Path("templates").mkdir(exist_ok=True)
    app.run(debug=True, port=5000)