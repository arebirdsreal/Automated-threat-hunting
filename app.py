from flask import Flask, render_template_string, jsonify
import json
import os

app = Flask(__name__)
JSON_PATH = "alerts.json"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>MITRE ATT&CK Threat Hunting Dashboard</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #1a1c23; color: #e2e8f0; margin: 40px; }
        h1 { color: #f56565; border-bottom: 2px solid #2d3748; padding-bottom: 10px; }
        .alert-card { background-color: #2d3748; border-left: 5px solid #e53e3e; padding: 15px; margin-bottom: 15px; border-radius: 4px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); animation: fadeIn 0.5s ease-in-out; }
        .timestamp { color: #a0aec0; font-size: 0.85em; }
        .badge { background-color: #e53e3e; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }
        .mitre-id { background-color: #3182ce; color: white; padding: 3px 8px; border-radius: 3px; font-size: 0.8em; font-weight: bold; }
        .no-alerts { color: #48bb78; font-size: 1.2em; text-align: center; margin-top: 50px; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
    </style>
    <script>
        async function fetchAlerts() {
            try {
                const response = await fetch('/api/alerts');
                const alerts = await response.json();
                const container = document.getElementById('alerts-container');
                
                if (!alerts || alerts.length === 0) {
                    container.innerHTML = '<p class="no-alerts">✅ System Clean. No active threats parsed in alerts.json.</p>';
                    return;
                }
                
                let html = '';
                alerts.forEach(alert => {
                    html += `
                        <div class="alert-card">
                            <p class="timestamp">🕒 ${alert.timestamp}</p>
                            <h3><span class="badge">${alert.alert_type}</span></h3>
                            <p><strong>Details:</strong> <code>${alert.details}</code></p>
                            <p><strong>Tactic:</strong> ${alert.mitre_tactic} | <strong>Technique:</strong> <span class="mitre-id">${alert.mitre_id}</span></p>
                        </div>
                    `;
                });
                container.innerHTML = html;
            } catch (err) {
                console.error(err);
            }
        }
        setInterval(fetchAlerts, 3000);
    </script>
</head>
<body>
    <h1>🚨 Live MITRE ATT&CK Telemetry Pipeline</h1>
    <div id="alerts-container">
        <p class="no-alerts">🔄 Connecting to telemetry stream...</p>
    </div>
    <script>
        fetchAlerts();
    </script>
</body>
</html>
"""

def get_raw_alerts():
    if os.path.exists(JSON_PATH):
        try:
            with open(JSON_PATH, "r") as f:
                content = f.read().strip()
                if not content:
                    return []
                alerts = json.loads(content)
                alerts.reverse()
                return alerts
        except (json.JSONDecodeError, PermissionError):
            return []
    return [] # Return clean empty array instead of crashing if file doesn't exist

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/alerts')
def api_alerts():
    return jsonify(get_raw_alerts())

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
