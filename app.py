"""
NetRecon - A cybersecurity tool for educational purposes and authorized network analysis.
"""

import io
import json
import logging
import os
import threading
import uuid

from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from modules.scanner import ReconScanner, validate_target

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("netrecon")

# ── App & rate limiter ────────────────────────────────────────────────────────
app = Flask(__name__)

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# In-memory job store
jobs = {}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
@limiter.limit("10 per minute")
def start_scan():
    """Start a new scan job."""
    data = request.get_json(silent=True) or {}
    raw_target = data.get("target", "").strip()
    scan_types = data.get("scan_types", ["ports", "whois", "headers", "dns"])

    if not raw_target:
        return jsonify({"error": "Target is required"}), 400

    target = validate_target(raw_target)
    if target is None:
        logger.warning("Rejected scan for blocked/invalid target: %s", raw_target)
        return jsonify({
            "error": "Invalid or disallowed target. "
                     "Private IPs and localhost are not permitted."
        }), 400

    if not isinstance(scan_types, list) or not scan_types:
        return jsonify({"error": "At least one scan module must be selected"}), 400

    allowed = {"ports", "whois", "headers", "dns", "ssl", "ip"}
    scan_types = [s for s in scan_types if s in allowed]
    if not scan_types:
        return jsonify({"error": "No valid scan modules selected"}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {
        "status": "running",
        "results": {},
        "progress": 0,
        "logs": [],
        "target": target,
    }

    logger.info("Scan started  job=%s target=%s modules=%s", job_id, target, scan_types)

    thread = threading.Thread(
        target=run_scan_job,
        args=(job_id, target, scan_types),
        daemon=True,
    )
    thread.start()

    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>", methods=["GET"])
def get_scan_status(job_id):
    """Poll scan job status and results."""
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    return jsonify(job)


@app.route("/api/scan/<job_id>/export", methods=["GET"])
def export_results(job_id):
    """Download completed scan results as a JSON file."""
    job = jobs.get(job_id)
    if not job:
        return jsonify({"error": "Job not found"}), 404
    if job["status"] != "complete":
        return jsonify({"error": "Scan not yet complete"}), 409

    target = job.get("target", "scan")
    payload = json.dumps(job, indent=2, default=str)
    filename = f"netrecon_{target.replace('.', '_')}.json"

    return send_file(
        io.BytesIO(payload.encode("utf-8")),
        mimetype="application/json",
        as_attachment=True,
        download_name=filename,
    )


def run_scan_job(job_id: str, target: str, scan_types: list) -> None:
    """Execute scan modules in sequence and update job state."""
    job = jobs[job_id]
    scanner = ReconScanner(target)

    steps = []
    if "ip"      in scan_types: steps.append(("ip",      "IP Information",        scanner.ip_info))
    if "ports"   in scan_types: steps.append(("ports",   "Port Scan",             scanner.scan_ports))
    if "whois"   in scan_types: steps.append(("whois",   "WHOIS Lookup",          scanner.whois_lookup))
    if "headers" in scan_types: steps.append(("headers", "HTTP Headers Analysis", scanner.analyze_headers))
    if "dns"     in scan_types: steps.append(("dns",     "DNS Enumeration",       scanner.dns_enum))
    if "ssl"     in scan_types: steps.append(("ssl",     "SSL/TLS Analysis",      scanner.ssl_check))

    total = len(steps)
    for i, (key, label, fn) in enumerate(steps):
        job["logs"].append(f"[*] Running {label}...")
        logger.debug("job=%s step=%s starting", job_id, key)
        try:
            result = fn()
            job["results"][key] = result
            job["logs"].append(f"[+] {label} complete.")
            logger.info("job=%s step=%s ok", job_id, key)
        except Exception as e:
            job["results"][key] = {"error": str(e)}
            job["logs"].append(f"[-] {label} failed: {e}")
            logger.error("job=%s step=%s error=%s", job_id, key, e, exc_info=True)

        job["progress"] = int(((i + 1) / total) * 100)

    job["status"] = "complete"
    job["logs"].append("[✓] Scan finished.")
    logger.info("Scan complete job=%s target=%s", job_id, target)


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    port  = int(os.getenv("PORT", "5000"))
    app.run(debug=debug, port=port)
