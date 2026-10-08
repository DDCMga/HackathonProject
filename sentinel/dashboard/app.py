"""Streamlit operator dashboard for Sentinel's SQLite alert store."""

import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from sentinel.audit import init_db, list_alerts, update_status

st.set_page_config(page_title="Sentinel Security Dashboard", layout="wide")
st.title("Sentinel Security Dashboard")
st.caption("Review detections, inspect evidence, and track response status.")

with st.sidebar:
    st.header("Data source")
    db_path = st.text_input("SQLite database", value=os.environ.get("SENTINEL_DB", "sentinel.db"))
    auto_refresh = st.checkbox("Refresh every 10 seconds", value=False)
    if st.button("Refresh now", use_container_width=True):
        st.rerun()
    if auto_refresh:
        try:
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=10_000, key="sentinel-refresh")
        except ImportError:
            st.info("Install streamlit-autorefresh to enable timed refresh.")

if not Path(db_path).exists():
    st.info("No alert database yet. Run Sentinel against a telemetry stream, then refresh this page.")
    st.stop()

try:
    connection = init_db(db_path)
    alerts = list_alerts(connection, limit=10000)
    connection.close()
except Exception as error:
    st.error(f"Could not read the alert database: {error}")
    st.stop()

if not alerts:
    st.info("The database is ready, but it has no alerts yet.")
    st.stop()

frame = pd.DataFrame(alerts)
all_bands = sorted(frame["classification"].dropna().unique().tolist())
all_categories = sorted(frame["threat_category"].dropna().unique().tolist())
all_statuses = sorted(frame["status"].dropna().unique().tolist())
with st.sidebar:
    st.header("Filters")
    selected_bands = st.multiselect("Risk band", all_bands, default=all_bands)
    selected_categories = st.multiselect("Threat category", all_categories, default=all_categories)
    selected_statuses = st.multiselect("Status", all_statuses, default=all_statuses)
    minimum_risk = st.slider("Minimum risk", 0, 100, 0)

filtered = frame[
    frame["classification"].isin(selected_bands)
    & frame["threat_category"].isin(selected_categories)
    & frame["status"].isin(selected_statuses)
    & (frame["risk_score"] >= minimum_risk)
].copy()
latest = frame["timestamp"].max()
counts = frame["classification"].value_counts()
cols = st.columns(4)
cols[0].metric("Total alerts", len(frame))
cols[1].metric("Malicious", int(counts.get("Malicious", 0)))
cols[2].metric("Suspicious", int(counts.get("Suspicious", 0)))
cols[3].metric("Latest alert", str(latest))

if filtered.empty:
    st.info("No alerts match these filters.")
else:
    st.subheader("Alerts")
    visible = filtered[["timestamp", "source_ip", "dest_ip", "classification",
                        "threat_category", "risk_score", "status", "alert_id"]]
    def risk_color(value):
        if value >= 71:
            return "background-color: #7f1d1d; color: white"
        if value >= 31:
            return "background-color: #854d0e; color: white"
        return "background-color: #166534; color: white"

    def style_risk_column(values):
        return [risk_color(value) for value in values]

    styled = visible.style.apply(style_risk_column, subset=["risk_score"])
    st.dataframe(styled, use_container_width=True, hide_index=True)

    left, middle, right = st.columns(3)
    with left:
        st.subheader("Risk distribution")
        histogram = filtered.groupby("risk_score").size().rename("alerts")
        st.bar_chart(histogram)
    with middle:
        st.subheader("Top 10 source IPs")
        top_sources = (filtered.groupby("source_ip")["risk_score"].max()
                       .sort_values(ascending=False).head(10))
        st.bar_chart(top_sources)
    with right:
        st.subheader("Threat categories")
        st.bar_chart(filtered["threat_category"].value_counts())

    st.subheader("Alert evidence")
    selected_id = st.selectbox("Select an alert", filtered["alert_id"].tolist())
    selected = next(row for row in alerts if row["alert_id"] == selected_id)
    detail_cols = st.columns(4)
    detail_cols[0].write(f"**Source:** {selected['source_ip']}")
    detail_cols[1].write(f"**Destination:** {selected.get('dest_ip') or 'Unknown'}")
    detail_cols[2].write(f"**Threat:** {selected['threat_category']}")
    detail_cols[3].write(f"**Risk:** {selected['risk_score']} ({selected['classification']})")
    st.json(selected.get("evidence_features", []))
    st.caption(f"Alert ID: {selected_id} ? Model: {selected.get('model_version', 'unknown')}")

    action_cols = st.columns([1, 1, 5])
    if action_cols[0].button("Mark reviewed", disabled=selected["status"] == "reviewed"):
        db = init_db(db_path)
        update_status(db, selected_id, "reviewed")
        db.close()
        st.rerun()
    if action_cols[1].button("Resolve", disabled=selected["status"] == "resolved"):
        db = init_db(db_path)
        update_status(db, selected_id, "resolved")
        db.close()
        st.rerun()

