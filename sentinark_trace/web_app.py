"""
Sentinark-Trace: Web Application Console (Flask)
Run via: python3 -m sentinark_trace.web_app
"""

from flask import Flask, render_template, request, jsonify
from .scanner import scan_url

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "Empty URL provided"}), 400

    report = scan_url(url, trace_hops=True)
    return jsonify(report)


def run_server(port=5003, debug=False):
    print(f"\n[*] Starting Sentinark-Trace Web Console on http://127.0.0.1:{port}")
    app.run(host="127.0.0.1", port=port, debug=debug)


if __name__ == "__main__":
    run_server()
