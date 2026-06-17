"""
app.py
------
Flask web app for reconsole.

Pages
    /            scan console (target field + preset checkboxes + custom field)
    /dashboard   nmap ports/services, smbmap and gobuster widgets, grouped by IP

API
    GET  /api/presets        catalogue of preset commands (for the checkboxes)
    GET  /api/tools          which tools are installed
    POST /api/scan           launch a scan (preset ids + custom + targets)
    GET  /api/runs           recent runs (status + links to output files)
    GET  /api/dashboard      grouped nmap/smbmap/gobuster results
    GET  /output/<run_id>    raw output .txt for a run (text/plain)

Run:  python app.py   ->   http://127.0.0.1:5000
"""

import atexit
import html as _html
import os
import queue
import re
import shutil
import threading

from flask import Flask, Response, jsonify, render_template, request

import database as db
import scanner

app = Flask(__name__)
_job_queue: "queue.Queue" = queue.Queue()


def _worker():
    while True:
        scan_id, preset_ids, custom_cmd, ips, ports, port_spec, hostname = _job_queue.get()
        try:
            scanner.run_job(scan_id, preset_ids, custom_cmd, ips, ports, port_spec, hostname)
        except Exception:                       # already recorded on the scan
            pass
        finally:
            _job_queue.task_done()


def start_worker():
    threading.Thread(target=_worker, daemon=True, name="scan-worker").start()


# ---- pages ----
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


# ---- api ----
@app.route("/api/presets")
def api_presets():
    # expose only display-relevant fields, grouped by tool for the UI
    grouped = {}
    for p in scanner.PRESETS:
        grouped.setdefault(p["tool"], []).append({
            "id": p["id"],
            "command": p["template"],
            "expands": scanner.LOOP_LABEL.get(p["loop"], ""),
        })
    return jsonify(grouped)


@app.route("/api/env")
def api_env():
    # the UI warns when not root, since the SYN / -A / -p- nmap presets need it
    return jsonify({"root": scanner.is_root()})


@app.route("/api/tools")
def api_tools():
    return jsonify(scanner.tools_status())


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    targets_raw = (data.get("targets") or "").strip()
    ports_raw = (data.get("ports") or "").strip()
    hostname_raw = (data.get("hostname") or "").strip()
    preset_ids = data.get("presets") or []
    custom_cmd = (data.get("custom") or "").strip()

    if not preset_ids and not custom_cmd:
        return jsonify({"error": "Select at least one preset or enter a custom command"}), 400

    # Work out which variables the selected commands actually reference, so we
    # only require (and validate) the fields that matter for this scan.
    need = {"ips": False, "ports": False, "hostname": False}
    for pid in preset_ids:
        p = scanner.PRESET_BY_ID.get(pid)
        if p:
            for k, v in scanner.template_vars(p["template"]).items():
                need[k] |= v
    if custom_cmd:
        for k, v in scanner.template_vars(custom_cmd).items():
            need[k] |= v

    ips, ports, port_spec, hostname = [], [], "", ""
    try:
        if need["ips"]:
            if not targets_raw:
                return jsonify({"error": "This selection needs target IP(s)"}), 400
            ips = scanner.parse_targets(targets_raw)
        if need["ports"]:
            if not ports_raw:
                return jsonify({"error": "This selection needs port(s)"}), 400
            ports, port_spec = scanner.parse_ports(ports_raw)
        if need["hostname"]:
            if not hostname_raw:
                return jsonify({"error": "This selection needs a hostname"}), 400
            hostname = scanner.validate_hostname(hostname_raw)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    label = targets_raw or hostname or "custom"
    scan_id = db.create_scan(label, len(ips))
    _job_queue.put((scan_id, preset_ids, custom_cmd, ips, ports, port_spec, hostname))
    return jsonify({
        "scan_id": scan_id,
        "ip_count": len(ips),
        "port_count": len(ports),
        "hostname": hostname,
    })


@app.route("/api/runs")
def api_runs():
    return jsonify(db.list_runs())


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify({
        "nmap": db.open_ports_by_ip(),
        "smbmap": db.findings_by_ip("smbmap"),
        "gobuster": db.findings_by_ip("gobuster"),
    })


@app.route("/api/run/<int:run_id>/stop", methods=["POST"])
def api_stop_run(run_id):
    run = db.get_run(run_id)
    if not run:
        return jsonify({"error": "unknown run"}), 404
    if run["status"] != "running":
        return jsonify({"status": run["status"], "note": "not running"})
    scanner.stop_run(run_id)
    db.finish_run(run_id, "stopped")
    return jsonify({"status": "stopped"})


@app.route("/api/stop_all", methods=["POST"])
def api_stop_all():
    # 1) drain not-yet-started jobs from the queue and mark their scans stopped
    drained = 0
    while True:
        try:
            scan_id = _job_queue.get_nowait()[0]
        except queue.Empty:
            break
        scanner.cancel_scan(scan_id)
        db.set_scan_status(scan_id, "stopped")
        _job_queue.task_done()
        drained += 1
    # 2) tell the worker to stop launching further runs for in-flight scans
    for s in db.list_scans():
        if s["status"] in ("running", "queued"):
            scanner.cancel_scan(s["id"])
    # 3) kill everything currently executing
    stopped = scanner.kill_all_procs()
    for rid in stopped:
        db.finish_run(rid, "stopped")
    return jsonify({"stopped_runs": len(stopped), "drained_jobs": drained})


@app.route("/api/run/<int:run_id>/delete", methods=["POST"])
def api_delete_run(run_id):
    """Remove a single run: stop it if running, delete its row + results, and
    delete its output/xml files from disk."""
    run = db.get_run(run_id)
    if not run:
        return jsonify({"error": "unknown run"}), 404
    if run["status"] == "running":
        scanner.stop_run(run_id)
    outfile = db.delete_run(run_id)
    if outfile:
        d = os.path.dirname(outfile)
        for p in (outfile, os.path.join(d, f"run_{run_id}.xml")):
            try:
                if os.path.exists(p):
                    os.remove(p)
            except OSError:
                pass
    return jsonify({"deleted": run_id})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    """Wipe ALL results: stop everything, clear the database, and delete every
    per-scan output file."""
    # 1) stop anything queued or running
    while True:
        try:
            scan_id = _job_queue.get_nowait()[0]
        except queue.Empty:
            break
        scanner.cancel_scan(scan_id)
        _job_queue.task_done()
    for s in db.list_scans():
        if s["status"] in ("running", "queued"):
            scanner.cancel_scan(s["id"])
    scanner.kill_all_procs()
    # 2) wipe the database
    db.reset_all()
    # 3) wipe the runs directory
    try:
        if os.path.isdir(scanner.RUNS_DIR):
            shutil.rmtree(scanner.RUNS_DIR)
        os.makedirs(scanner.RUNS_DIR, exist_ok=True)
    except OSError:
        pass
    return jsonify({"reset": True})


@app.route("/output/<int:run_id>")
def output(run_id):
    """Live view of a run's output. Auto-refreshes while the run is in
    progress so the text fills in as the tool prints it; static once done.
    The raw .txt is one click away via the download link."""
    run = db.get_run(run_id)
    if not run:
        return Response("Unknown run.", mimetype="text/plain", status=404)

    text = "(waiting for output…)"
    if run.get("output_file") and os.path.exists(run["output_file"]):
        with open(run["output_file"], "r", errors="replace") as f:
            text = f.read() or "(no output yet)"

    running = run["status"] in ("running", "queued")
    refresh = '<meta http-equiv="refresh" content="2">' if running else ""
    color = {"running": "#e8a33d", "completed": "#3db8b0",
             "error": "#e5534b"}.get(run["status"], "#6e7a8a")
    tail = "<script>window.scrollTo(0,document.body.scrollHeight)</script>" if running else ""

    html = (
        f'<!doctype html><html><head><meta charset="utf-8">{refresh}'
        f'<title>run #{run_id}</title><style>'
        'body{margin:0;background:#0e1116;color:#c9d4e0;'
        'font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace;font-size:13px;}'
        '.bar{position:sticky;top:0;background:#161b22;border-bottom:1px solid #232a33;'
        'padding:10px 18px;display:flex;gap:16px;align-items:center;}'
        f'.st{{color:{color};text-transform:uppercase;font-size:11px;letter-spacing:.6px;}}'
        '.bar a{color:#3db8b0;margin-left:auto;text-decoration:none;}'
        'pre{margin:0;padding:18px;white-space:pre-wrap;word-break:break-word;line-height:1.45;}'
        '</style></head><body>'
        f'<div class="bar"><span class="st">{run["status"]}{" · live" if running else ""}</span>'
        f'<span style="color:#6e7a8a">run #{run_id} · {_html.escape(run["tool"] or "")}</span>'
        f'<a href="/output/{run_id}/raw" download>download .txt &darr;</a></div>'
        f'<pre>{_html.escape(text)}</pre>{tail}</body></html>'
    )
    return Response(html, mimetype="text/html")


@app.route("/output/<int:run_id>/raw")
def output_raw(run_id):
    run = db.get_run(run_id)
    if not run or not run.get("output_file") or not os.path.exists(run["output_file"]):
        return Response("No output recorded for this run.", mimetype="text/plain", status=404)
    with open(run["output_file"], "r", errors="replace") as f:
        return Response(f.read(), mimetype="text/plain")


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _tail_lines(path: str, n: int) -> list:
    """Return the last n lines of a file efficiently (reads only the tail)."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            read = min(end, 131072)           # last 128KB comfortably covers 100 lines
            fh.seek(end - read)
            data = fh.read()
    except OSError:
        return []
    text = _ANSI.sub("", data.decode("utf-8", "replace"))
    return text.splitlines()[-n:]


@app.route("/api/run/<int:run_id>/tail")
def api_run_tail(run_id):
    """Up to the last 100 lines of a run's output, for the live block in the
    Console (which shows ~20 at a time and scrolls for the rest)."""
    run = db.get_run(run_id)
    if not run:
        return jsonify({"id": run_id, "status": "unknown", "lines": []}), 404
    lines = []
    if run.get("output_file") and os.path.exists(run["output_file"]):
        lines = _tail_lines(run["output_file"], 100)
    return jsonify({"id": run_id, "status": run["status"], "lines": lines})


if __name__ == "__main__":
    db.init_db()
    os.makedirs(scanner.RUNS_DIR, exist_ok=True)
    start_worker()
    # Make sure no scan keeps running after the app exits — kill every child
    # process on normal exit, on Ctrl-C, and on SIGTERM.
    atexit.register(scanner.kill_all_procs)
    try:
        app.run(host="127.0.0.1", port=5000, debug=False)
    finally:
        scanner.kill_all_procs()
