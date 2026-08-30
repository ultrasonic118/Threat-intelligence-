# Campus Sentinel — Streamlit Dashboard

A hackathon-ready proof of concept for **Campus Network Anomaly Detection**, based on the supplied project brief. The app presents a Security Operations Center-style dashboard for network-flow monitoring without requiring a live packet capture.

## Included in the demo

The dashboard includes a live-looking anomaly-score telemetry chart, attack distribution chart, KPI cards, severity filters, an alert table, a selected-alert detail panel, and a SHAP-style explanation of the top contributing flow features. The **Simulate attack** button injects a clearly labeled high-confidence port-scan event into the feed so the full detection-to-alert flow can be shown during a jury walkthrough.

The current data source is deterministic synthetic replay data for demonstration only. The UI is structured so the replay source can later be replaced by an NSL-KDD-style dataset, a live flow collector, or a FastAPI `/predict` endpoint.

## Run locally

```bash
cd campus_network_dashboard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Then open the local URL shown by Streamlit, usually `http://localhost:8501`.

## Suggested 90-second demo

1. Start on the overview screen and explain the pipeline: traffic → features → model score → alerts.
2. Point out the KPI row and the red anomaly points in the telemetry chart.
3. Select an alert to show the source/destination pair and SHAP-style feature explanation.
4. Click **Simulate attack** and show the new high-severity port-scan row appearing in the alert table.
5. Toggle **Auto-refresh demo feed** to make the screen feel live.

## Productionization path

For a production version, connect the flow table to real telemetry, persist alerts in SQLite or another database, expose model inference through FastAPI, replace the placeholder explanation with actual SHAP values, and add a Discord or Telegram webhook for high-severity events.
